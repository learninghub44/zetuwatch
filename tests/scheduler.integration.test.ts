import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  claimDueMonitors,
  finalizeMonitorCheck,
  releaseMonitorClaim
} from "../packages/scheduler-core/src/claims";

const sqlTime = (value: string): string =>
  new Date(value).toISOString().slice(0, 19).replace("T", " ");

async function createMonitor(options: {
  nextCheckAt: string;
  enabled?: boolean;
  consecutiveFailures?: number;
}): Promise<string> {
  const organizationId = crypto.randomUUID();
  const monitorId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Scheduler test workspace", "scheduler-" + organizationId),
    env.DB.prepare(`INSERT INTO monitors
      (id, organization_id, name, target_url, is_enabled, consecutive_failures, next_check_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .bind(
        monitorId,
        organizationId,
        "Scheduler fixture",
        "https://monitor.example.com/health",
        options.enabled === false ? 0 : 1,
        options.consecutiveFailures ?? 0,
        sqlTime(options.nextCheckAt)
      )
  ]);
  return monitorId;
}

describe("D1 monitor scheduler claims", () => {
  it("claims only due enabled monitors and respects the batch limit", async () => {
    const now = "2026-11-10T09:00:00.000Z";
    const earliest = await createMonitor({ nextCheckAt: "2026-11-10T08:00:00.000Z" });
    const later = await createMonitor({ nextCheckAt: "2026-11-10T08:30:00.000Z" });
    await createMonitor({ nextCheckAt: "2026-11-10T09:01:00.000Z" });
    await createMonitor({ nextCheckAt: "2026-11-10T08:00:00.000Z", enabled: false });

    const firstBatch = await claimDueMonitors(env.DB, {
      now,
      limit: 1,
      token: "scheduler-claim-token-0001"
    });
    expect(firstBatch.map((monitor) => monitor.id)).toEqual([earliest]);

    const secondBatch = await claimDueMonitors(env.DB, {
      now,
      limit: 10,
      token: "scheduler-claim-token-0002"
    });
    expect(secondBatch.map((monitor) => monitor.id)).toEqual([later]);
    expect(firstBatch[0].leaseUntil).toBe("2026-11-10T09:02:00.000Z");
  });

  it("does not allow overlapping invocations to claim the same due monitor", async () => {
    const monitorId = await createMonitor({ nextCheckAt: "2026-11-10T08:59:00.000Z" });
    const now = "2026-11-10T09:00:00.000Z";

    const [first, second] = await Promise.all([
      claimDueMonitors(env.DB, { now, token: "scheduler-concurrent-token-1" }),
      claimDueMonitors(env.DB, { now, token: "scheduler-concurrent-token-2" })
    ]);

    expect(first.length + second.length).toBe(1);
    expect([...first, ...second][0].id).toBe(monitorId);
  });

  it("reclaims an expired lease and rejects stale release attempts", async () => {
    const monitorId = await createMonitor({ nextCheckAt: "2026-11-10T08:59:00.000Z" });
    const first = await claimDueMonitors(env.DB, {
      now: "2026-11-10T09:00:00.000Z",
      leaseMs: 30_000,
      token: "scheduler-expiring-token-1"
    });
    expect(first).toHaveLength(1);

    const reclaimed = await claimDueMonitors(env.DB, {
      now: "2026-11-10T09:00:31.000Z",
      leaseMs: 30_000,
      token: "scheduler-reclaimed-token-2"
    });
    expect(reclaimed.map((monitor) => monitor.id)).toEqual([monitorId]);
    expect(await releaseMonitorClaim(env.DB, monitorId, "scheduler-expiring-token-1")).toBe(false);
    expect(await releaseMonitorClaim(env.DB, monitorId, "scheduler-reclaimed-token-2")).toBe(true);

    const availableAgain = await claimDueMonitors(env.DB, {
      now: "2026-11-10T09:00:32.000Z",
      token: "scheduler-retry-claim-token-3"
    });
    expect(availableAgain.map((monitor) => monitor.id)).toEqual([monitorId]);
  });

  it("persists a check and advances the schedule only for the current lease", async () => {
    const monitorId = await createMonitor({
      nextCheckAt: "2026-11-10T08:59:00.000Z",
      consecutiveFailures: 0
    });
    const claimed = await claimDueMonitors(env.DB, {
      now: "2026-11-10T09:00:00.000Z",
      token: "scheduler-finalize-token-01"
    });
    expect(claimed).toHaveLength(1);

    const input = {
      monitorId,
      leaseToken: claimed[0].leaseToken,
      checkedAt: "2026-11-10T09:00:01.000Z",
      nextCheckAt: "2026-11-10T09:05:01.000Z",
      isUp: false,
      statusCode: 503,
      responseTimeMs: 82,
      errorCode: "HTTP_STATUS_MISMATCH",
      checkId: crypto.randomUUID()
    };
    expect(await finalizeMonitorCheck(env.DB, input)).toBe(true);
    expect(await finalizeMonitorCheck(env.DB, input)).toBe(false);

    const monitor = await env.DB.prepare(
      "SELECT consecutive_failures, check_lease_token, next_check_at FROM monitors WHERE id = ?"
    ).bind(monitorId).first<{
      consecutive_failures: number;
      check_lease_token: string | null;
      next_check_at: string;
    }>();
    const checks = await env.DB.prepare(
      "SELECT id, is_up, status_code, response_time_ms, error_code FROM monitor_checks WHERE monitor_id = ?"
    ).bind(monitorId).all<{
      id: string;
      is_up: number;
      status_code: number;
      response_time_ms: number;
      error_code: string;
    }>();

    expect(monitor).toEqual({
      consecutive_failures: 1,
      check_lease_token: null,
      next_check_at: "2026-11-10 09:05:01"
    });
    expect(checks.results).toHaveLength(1);
    expect(checks.results[0]).toMatchObject({
      is_up: 0,
      status_code: 503,
      response_time_ms: 82,
      error_code: "HTTP_STATUS_MISMATCH"
    });
  });

  it("resets the failure streak after a successful check", async () => {
    const monitorId = await createMonitor({
      nextCheckAt: "2026-11-10T08:59:00.000Z",
      consecutiveFailures: 4
    });
    const [claim] = await claimDueMonitors(env.DB, {
      now: "2026-11-10T09:00:00.000Z",
      token: "scheduler-recovery-token-01"
    });
    expect(claim).toBeDefined();

    expect(await finalizeMonitorCheck(env.DB, {
      monitorId,
      leaseToken: claim.leaseToken,
      checkedAt: "2026-11-10T09:00:02.000Z",
      nextCheckAt: "2026-11-10T09:05:02.000Z",
      isUp: true,
      statusCode: 200,
      responseTimeMs: 35
    })).toBe(true);

    const row = await env.DB.prepare(
      "SELECT consecutive_failures FROM monitors WHERE id = ?"
    ).bind(monitorId).first<{ consecutive_failures: number }>();
    expect(row?.consecutive_failures).toBe(0);
  });

  it("rejects unsafe claim bounds and invalid check results", async () => {
    await expect(claimDueMonitors(env.DB, {
      limit: 26,
      token: "scheduler-invalid-limit-token"
    })).rejects.toThrow("SCHEDULER_LIMIT_INVALID");
    await expect(claimDueMonitors(env.DB, {
      leaseMs: 29_999,
      token: "scheduler-invalid-lease-token"
    })).rejects.toThrow("SCHEDULER_LEASE_INVALID");

    await expect(finalizeMonitorCheck(env.DB, {
      monitorId: crypto.randomUUID(),
      leaseToken: "scheduler-invalid-result-token",
      checkedAt: "2026-11-10T09:00:00.000Z",
      nextCheckAt: "2026-11-10T09:05:00.000Z",
      isUp: false,
      statusCode: 700,
      responseTimeMs: 1
    })).rejects.toThrow("SCHEDULER_STATUS_INVALID");
  });
});
