import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  claimDueMonitors,
  finalizeMonitorCheck
} from "../packages/scheduler-core/src/claims";

const sqlTime = (value: string): string =>
  new Date(value).toISOString().slice(0, 19).replace("T", " ");

async function createMonitor(): Promise<string> {
  const organizationId = crypto.randomUUID();
  const monitorId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Incident test workspace", "incident-" + organizationId),
    env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url, next_check_at) VALUES (?, ?, ?, ?, ?)")
      .bind(
        monitorId,
        organizationId,
        "Incident fixture",
        "https://incident.example.com/health",
        sqlTime("2026-11-10T08:59:00.000Z")
      )
  ]);
  return monitorId;
}

async function runCheck(
  monitorId: string,
  scheduledAt: string,
  isUp: boolean,
  sequence: number
): Promise<string> {
  const claims = await claimDueMonitors(env.DB, {
    now: scheduledAt,
    token: "incident-worker-lease-" + sequence
  });
  const claim = claims.find((item) => item.id === monitorId);
  if (!claim) throw new Error("INCIDENT_TEST_MONITOR_NOT_CLAIMED");

  const checkedAt = new Date(Date.parse(scheduledAt) + 1_000).toISOString();
  const nextCheckAt = new Date(Date.parse(checkedAt) + 300_000).toISOString();
  const finalized = await finalizeMonitorCheck(env.DB, {
    monitorId,
    leaseToken: claim.leaseToken,
    checkedAt,
    nextCheckAt,
    isUp,
    statusCode: isUp ? 200 : 503,
    responseTimeMs: isUp ? 28 : 90,
    errorCode: isUp ? null : "HTTP_STATUS_MISMATCH"
  });
  if (!finalized) throw new Error("INCIDENT_TEST_CHECK_NOT_FINALIZED");
  return nextCheckAt;
}

async function getIncidents(monitorId: string): Promise<Array<{
  id: string;
  status: string;
  resolved_at: string | null;
}>> {
  const result = await env.DB.prepare(
    "SELECT id, status, resolved_at FROM incidents WHERE monitor_id = ? ORDER BY started_at ASC"
  ).bind(monitorId).all<{ id: string; status: string; resolved_at: string | null }>();
  return result.results;
}

async function getEventTypes(incidentId: string): Promise<string[]> {
  const result = await env.DB.prepare(
    "SELECT event_type FROM incident_events WHERE incident_id = ? ORDER BY created_at ASC, id ASC"
  ).bind(incidentId).all<{ event_type: string }>();
  return result.results.map((event) => event.event_type);
}

describe("D1 incident lifecycle", () => {
  it("confirms after consecutive failures and deduplicates an active incident", async () => {
    const monitorId = await createMonitor();
    let nextCheck = "2026-11-10T09:00:00.000Z";

    nextCheck = await runCheck(monitorId, nextCheck, false, 1);
    expect(await getIncidents(monitorId)).toHaveLength(0);

    nextCheck = await runCheck(monitorId, nextCheck, false, 2);
    let incidents = await getIncidents(monitorId);
    expect(incidents).toHaveLength(1);
    expect(incidents[0].status).toBe("investigating");
    expect(incidents[0].resolved_at).toBeNull();

    await runCheck(monitorId, nextCheck, false, 3);
    incidents = await getIncidents(monitorId);
    expect(incidents).toHaveLength(1);
    expect(await getEventTypes(incidents[0].id)).toEqual(["incident.opened"]);
  });

  it("moves through monitoring and resolves only after the recovery threshold", async () => {
    const monitorId = await createMonitor();
    let nextCheck = "2026-11-10T09:00:00.000Z";

    nextCheck = await runCheck(monitorId, nextCheck, false, 11);
    nextCheck = await runCheck(monitorId, nextCheck, false, 12);
    const [incident] = await getIncidents(monitorId);
    expect(incident.status).toBe("investigating");

    nextCheck = await runCheck(monitorId, nextCheck, true, 13);
    let incidents = await getIncidents(monitorId);
    expect(incidents[0].status).toBe("monitoring");
    expect(incidents[0].resolved_at).toBeNull();

    await runCheck(monitorId, nextCheck, true, 14);
    incidents = await getIncidents(monitorId);
    expect(incidents[0].status).toBe("resolved");
    expect(incidents[0].resolved_at).not.toBeNull();
    expect(await getEventTypes(incident.id)).toEqual([
      "incident.opened",
      "incident.monitoring",
      "incident.resolved"
    ]);

    await expect(env.DB.prepare(
      "UPDATE incident_events SET message = 'tampered' WHERE incident_id = ?"
    ).bind(incident.id).run()).rejects.toThrow("INCIDENT_EVENTS_IMMUTABLE");
  });

  it("reopens the same incident when a failure interrupts recovery", async () => {
    const monitorId = await createMonitor();
    let nextCheck = "2026-11-10T09:00:00.000Z";

    nextCheck = await runCheck(monitorId, nextCheck, false, 21);
    nextCheck = await runCheck(monitorId, nextCheck, false, 22);
    const [opened] = await getIncidents(monitorId);

    nextCheck = await runCheck(monitorId, nextCheck, true, 23);
    expect((await getIncidents(monitorId))[0].status).toBe("monitoring");

    await runCheck(monitorId, nextCheck, false, 24);
    const incidents = await getIncidents(monitorId);
    expect(incidents).toHaveLength(1);
    expect(incidents[0].id).toBe(opened.id);
    expect(incidents[0].status).toBe("investigating");
    expect(await getEventTypes(opened.id)).toEqual([
      "incident.opened",
      "incident.monitoring",
      "incident.reopened"
    ]);
  });
});
