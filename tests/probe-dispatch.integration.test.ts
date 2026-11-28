import { env } from "cloudflare:workers";
import worker from "../apps/api/src/index";
import { describe, expect, it } from "vitest";
import { claimDueMonitors } from "../packages/scheduler-core/src/claims";
import { dispatchDueMonitors, type ProbeDispatchEnv } from "../packages/scheduler-core/src/dispatch";

const BASE_NOW = new Date("2026-11-22T06:30:00.000Z");
const sqlTime = (value: Date): string => value.toISOString().slice(0, 19).replace("T", " ");
const dispatchEnv: ProbeDispatchEnv = {
  DB: env.DB,
  PROBES_ENABLED: "true",
  PROBE_AGENT_URL: "https://probe.example.test/v1/probe",
  PROBE_SHARED_SECRET: "test-only-probe-secret-with-at-least-32-bytes"
};
const healthyResult = {
  isUp: true,
  statusCode: 200,
  responseTimeMs: 25,
  errorCode: null,
  redirectCount: 0
};

async function createOrganization(name: string): Promise<string> {
  const organizationId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
    .bind(organizationId, name, "dispatch-" + organizationId).run();
  return organizationId;
}

async function createMonitor(organizationId: string, name = "Dispatch fixture"): Promise<string> {
  const monitorId = crypto.randomUUID();
  await env.DB.prepare(`INSERT INTO monitors
    (id, organization_id, name, target_url, method, expected_status, interval_seconds, timeout_ms, next_check_at)
    VALUES (?, ?, ?, ?, 'GET', 200, 300, 5000, ?)`)
    .bind(
      monitorId,
      organizationId,
      name,
      "https://monitor.example.com/health",
      sqlTime(new Date(BASE_NOW.getTime() - 60_000))
    ).run();
  return monitorId;
}

async function checkCount(monitorId: string): Promise<number> {
  const row = await env.DB.prepare("SELECT COUNT(*) AS count FROM monitor_checks WHERE monitor_id = ?")
    .bind(monitorId).first<{ count: number }>();
  return row?.count ?? 0;
}

describe("bounded scheduled probe dispatch", () => {
  it("rejects batch and concurrency bounds that could outlive the lease or exceed Worker connections", async () => {
    await expect(dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      limit: 16,
      clock: () => new Date(BASE_NOW),
      probe: async () => healthyResult
    })).rejects.toThrow("SCHEDULER_LIMIT_INVALID");
    await expect(dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      concurrency: 6,
      clock: () => new Date(BASE_NOW),
      probe: async () => healthyResult
    })).rejects.toThrow("SCHEDULER_CONCURRENCY_INVALID");
  });

  it("does not claim work while probe execution is disabled", async () => {
    const organizationId = await createOrganization("Disabled dispatch");
    const monitorId = await createMonitor(organizationId);
    const summary = await dispatchDueMonitors(
      { ...dispatchEnv, PROBES_ENABLED: "false" },
      {
        now: BASE_NOW,
        clock: () => new Date(BASE_NOW),
        probe: async () => healthyResult
      }
    );

    expect(summary).toMatchObject({
      skipped: true,
      reason: "PROBES_DISABLED",
      claimed: 0,
      finalized: 0
    });
    const monitor = await env.DB.prepare("SELECT check_lease_token FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ check_lease_token: string | null }>();
    expect(monitor?.check_lease_token).toBeNull();
    expect(await checkCount(monitorId)).toBe(0);
  });

  it("rejects an invalid configured agent endpoint before claiming due work", async () => {
    const organizationId = await createOrganization("Invalid agent endpoint");
    const monitorId = await createMonitor(organizationId);
    const summary = await dispatchDueMonitors(
      { ...dispatchEnv, PROBE_AGENT_URL: "http://probe.example.test/v1/probe" },
      { now: BASE_NOW, clock: () => new Date(BASE_NOW), probe: async () => healthyResult }
    );

    expect(summary).toMatchObject({
      skipped: true,
      reason: "PROBE_AGENT_CONFIGURATION_INVALID",
      claimed: 0
    });
    const monitor = await env.DB.prepare("SELECT check_lease_token FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ check_lease_token: string | null }>();
    expect(monitor?.check_lease_token).toBeNull();
  });

  it("enforces per-workspace claim quotas and persists only valid probe results", async () => {
    const organizationA = await createOrganization("Fairness workspace A");
    const organizationB = await createOrganization("Fairness workspace B");
    const monitorsA = await Promise.all(Array.from({ length: 3 }, (_, index) => createMonitor(organizationA, "A-" + index)));
    const monitorsB = await Promise.all(Array.from({ length: 3 }, (_, index) => createMonitor(organizationB, "B-" + index)));
    let active = 0;
    let maximumActive = 0;

    const summary = await dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      clock: () => new Date(BASE_NOW),
      limit: 4,
      perOrganizationLimit: 2,
      concurrency: 2,
      probe: async (endpoint, secret, job) => {
        expect(endpoint).toBe(dispatchEnv.PROBE_AGENT_URL);
        expect(secret).toBe(dispatchEnv.PROBE_SHARED_SECRET);
        expect(job.method).toBe("GET");
        expect(job.maxRedirects).toBe(0);
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await Promise.resolve();
        active -= 1;
        return healthyResult;
      }
    });

    expect(summary).toMatchObject({ skipped: false, claimed: 4, finalized: 4, deferred: 0, stale: 0 });
    expect(maximumActive).toBeLessThanOrEqual(2);
    const ids = monitorsA.concat(monitorsB);
    const placeholders = ids.map(() => "?").join(",");
    const rows = await env.DB.prepare(`SELECT m.organization_id AS organizationId, COUNT(c.id) AS count
      FROM monitors m LEFT JOIN monitor_checks c ON c.monitor_id = m.id
      WHERE m.organization_id IN (?, ?) AND m.id IN (${placeholders})
      GROUP BY m.organization_id ORDER BY m.organization_id`)
      .bind(organizationA, organizationB, ...ids).all<{ organizationId: string; count: number }>();
    expect(rows.results.map(row => row.count).sort()).toEqual([2, 2]);
  });

  it("enforces the workspace in-flight quota across overlapping claim invocations", async () => {
    const organizationId = await createOrganization("Overlapping workspace claims");
    const monitorIds = await Promise.all(Array.from({ length: 3 }, (_, index) =>
      createMonitor(organizationId, "overlap-" + index)
    ));

    const [first, second] = await Promise.all([
      claimDueMonitors(env.DB, {
        now: BASE_NOW,
        limit: 10,
        perOrganizationLimit: 2,
        token: "overlap-claim-invocation-0001"
      }),
      claimDueMonitors(env.DB, {
        now: BASE_NOW,
        limit: 10,
        perOrganizationLimit: 2,
        token: "overlap-claim-invocation-0002"
      })
    ]);

    expect(first.length + second.length).toBe(2);
    const active = await env.DB.prepare(`SELECT COUNT(*) AS count FROM monitors
      WHERE id IN (${monitorIds.map(() => "?").join(",")})
        AND check_lease_token IS NOT NULL AND check_lease_until > ?`)
      .bind(...monitorIds, BASE_NOW.toISOString()).first<{ count: number }>();
    expect(active?.count).toBe(2);
  });

  it("defers agent outages without recording a false customer failure", async () => {
    const organizationId = await createOrganization("Agent outage");
    const monitorId = await createMonitor(organizationId);
    const summary = await dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      clock: () => new Date(BASE_NOW),
      probe: async () => { throw new Error("PROBE_AGENT_UNAVAILABLE"); }
    });

    expect(summary).toMatchObject({ claimed: 1, finalized: 0, deferred: 1, stale: 0 });
    expect(await checkCount(monitorId)).toBe(0);
    const monitor = await env.DB.prepare("SELECT next_check_at, check_lease_token FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ next_check_at: string; check_lease_token: string | null }>();
    expect(monitor).toEqual({
      next_check_at: sqlTime(new Date(BASE_NOW.getTime() + 30_000)),
      check_lease_token: null
    });

    const beforeRetry = await claimDueMonitors(env.DB, {
      now: new Date(BASE_NOW.getTime() + 29_000),
      token: "dispatch-retry-before-0001"
    });
    expect(beforeRetry.some(item => item.id === monitorId)).toBe(false);
    const afterRetry = await claimDueMonitors(env.DB, {
      now: new Date(BASE_NOW.getTime() + 31_000),
      token: "dispatch-retry-after-00001"
    });
    expect(afterRetry.some(item => item.id === monitorId)).toBe(true);
  });

  it("persists an actual failed HTTP response as a check result", async () => {
    const organizationId = await createOrganization("Real failed response");
    const monitorId = await createMonitor(organizationId);
    const summary = await dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      clock: () => new Date(BASE_NOW),
      probe: async () => ({
        isUp: false,
        statusCode: 503,
        responseTimeMs: 83,
        errorCode: "HTTP_STATUS_MISMATCH",
        redirectCount: 0
      })
    });

    expect(summary).toMatchObject({ claimed: 1, finalized: 1, deferred: 0 });
    const check = await env.DB.prepare("SELECT is_up, status_code, response_time_ms, error_code FROM monitor_checks WHERE monitor_id = ?")
      .bind(monitorId).first<{ is_up: number; status_code: number; response_time_ms: number; error_code: string }>();
    expect(check).toEqual({
      is_up: 0,
      status_code: 503,
      response_time_ms: 83,
      error_code: "HTTP_STATUS_MISMATCH"
    });
  });

  it("rejects malformed agent results and defers instead of persisting them", async () => {
    const organizationId = await createOrganization("Malformed agent result");
    const monitorId = await createMonitor(organizationId);
    const summary = await dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      clock: () => new Date(BASE_NOW),
      probe: async () => ({ isUp: true } as never)
    });

    expect(summary).toMatchObject({ claimed: 1, finalized: 0, deferred: 1 });
    expect(await checkCount(monitorId)).toBe(0);
  });

  it("does not finalize a result after another invocation has reclaimed its lease", async () => {
    const organizationId = await createOrganization("Stale result");
    const monitorId = await createMonitor(organizationId);
    const replacementToken = "replacement-lease-token-00001";
    const summary = await dispatchDueMonitors(dispatchEnv, {
      now: BASE_NOW,
      clock: () => new Date(BASE_NOW),
      probe: async () => {
        const reclaimed = await claimDueMonitors(env.DB, {
          now: new Date(BASE_NOW.getTime() + 181_000),
          token: replacementToken
        });
        expect(reclaimed.some(item => item.id === monitorId)).toBe(true);
        return healthyResult;
      }
    });

    expect(summary).toMatchObject({ claimed: 1, finalized: 0, deferred: 0, stale: 1 });
    expect(await checkCount(monitorId)).toBe(0);
    const monitor = await env.DB.prepare("SELECT check_lease_token FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ check_lease_token: string | null }>();
    expect(monitor?.check_lease_token).toBe(replacementToken);
  });

  it("keeps the scheduled monitor runner disabled when the Cron Trigger fires without probe bindings", async () => {
    const organizationId = await createOrganization("Cron remains gated");
    const monitorId = await createMonitor(organizationId);

    await worker.scheduled(
      { cron: "*/1 * * * *", scheduledTime: BASE_NOW.getTime() } as ScheduledController,
      { DB: env.DB, PUBLIC_APP_URL: "http://localhost:8787" } as never,
      {} as ExecutionContext
    );

    expect(await checkCount(monitorId)).toBe(0);
    const monitor = await env.DB.prepare("SELECT check_lease_token FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ check_lease_token: string | null }>();
    expect(monitor?.check_lease_token).toBeNull();
  });


});
