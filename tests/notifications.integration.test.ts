import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { finalizeMonitorCheck } from "../packages/scheduler-core/src/claims";

type Role = "owner" | "admin" | "member" | "viewer";
interface Identity {
  userId: string;
  organizationId: string;
  sessionToken: string;
  email: string;
}

const sha256 = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
};

async function createIdentity(role: Role = "owner"): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const sessionToken = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
  const email = `${userId}@example.test`;
  await env.DB.batch([
    env.DB.prepare("INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
      .bind(userId, email, "Notification test user"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Notification workspace", `notify-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)")
      .bind(organizationId, userId, role),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, await sha256(sessionToken), new Date(Date.now() + 3_600_000).toISOString())
  ]);
  return { userId, organizationId, sessionToken, email };
}

function api(
  path: string,
  identity: Identity,
  options: { method?: string; body?: Record<string, unknown>; apiKey?: string } = {}
): Promise<Response> {
  const headers = new Headers({ "cf-connecting-ip": crypto.randomUUID() });
  if (identity.sessionToken) headers.set("cookie", `zw_session=${identity.sessionToken}`);
  if (options.apiKey) headers.set("authorization", `Bearer ${options.apiKey}`);
  if (options.body) headers.set("content-type", "application/json");
  return exports.default.fetch(new Request(`https://api.zetuwatch.test${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  }));
}

async function createEmailChannel(identity: Identity): Promise<{ id: string; destination: string }> {
  const response = await api(`/v1/organizations/${identity.organizationId}/notification-channels`, identity, {
    method: "POST",
    body: { channelType: "email" }
  });
  expect(response.status).toBe(201);
  const payload = await response.json() as { channel: { id: string; destination: string } };
  return payload.channel;
}

async function createMonitor(organizationId: string): Promise<string> {
  const monitorId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)")
    .bind(monitorId, organizationId, "Payments API", "https://payments.example.test/health").run();
  return monitorId;
}

async function createIncident(monitorId: string): Promise<{ id: string; eventId: string }> {
  const incidentId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, 'investigating', ?)")
      .bind(incidentId, monitorId, "2026-11-18 09:00:00", "The monitor failed consecutive checks."),
    env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at) VALUES (?, ?, 'incident.opened', ?, ?)")
      .bind(eventId, incidentId, "Incident opened after consecutive failures.", "2026-11-18 09:00:00")
  ]);
  return { id: incidentId, eventId };
}

async function queueDelivery(identity: Identity, monitorId: string, channelId: string): Promise<string> {
  const incident = await createIncident(monitorId);
  const deliveryId = crypto.randomUUID();
  await env.DB.prepare(`INSERT INTO notification_deliveries
    (id, organization_id, incident_id, channel_id, provider, status, attempt_count,
     next_attempt_at, event_id, event_type, recipient_email)
    VALUES (?, ?, ?, ?, 'resend', 'queued', 0, ?, ?, 'incident.opened', ?)`)
    .bind(deliveryId, identity.organizationId, incident.id, channelId,
      new Date(Date.now() - 1000).toISOString(), incident.eventId, identity.email).run();
  return deliveryId;
}

async function runScheduled(now: Date): Promise<void> {
  const handler = exports.default as unknown as {
    scheduled(controller: ScheduledController, workerEnv: typeof env, context: ExecutionContext): Promise<void>;
  };
  await handler.scheduled({
    cron: "*/1 * * * *",
    scheduledTime: now.getTime(),
    type: "scheduled"
  } as ScheduledController, env, {} as ExecutionContext);
}

describe("email notification channels and delivery", () => {
  it("only lets a verified member subscribe their own email address", async () => {
    const owner = await createIdentity("owner");
    const created = await api(`/v1/organizations/${owner.organizationId}/notification-channels`, owner, {
      method: "POST",
      body: { channelType: "email", email: "someone-else@example.test" }
    });
    expect(created.status).toBe(400);
    expect(await created.json()).toMatchObject({ error: "EMAIL_MUST_MATCH_VERIFIED_ACCOUNT" });

    const channel = await createEmailChannel(owner);
    expect(channel.destination).toBe(owner.email);
    const listed = await api(`/v1/organizations/${owner.organizationId}/notification-channels`, owner);
    expect(await listed.json()).toMatchObject({
      channels: [expect.objectContaining({ id: channel.id, destination: owner.email, isEnabled: 1 })]
    });
  });

  it("rejects viewer, API-key and cross-tenant channel management", async () => {
    const viewer = await createIdentity("viewer");
    const denied = await api(`/v1/organizations/${viewer.organizationId}/notification-channels`, viewer, {
      method: "POST", body: { channelType: "email" }
    });
    expect(denied.status).toBe(403);

    const owner = await createIdentity("owner");
    const keySecret = "zw_live_" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    await env.DB.prepare("INSERT INTO api_keys (id, organization_id, created_by, name, key_prefix, key_hash) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), owner.organizationId, owner.userId, "Read key", keySecret.slice(0, 16), await sha256(keySecret)).run();
    const apiKeyDenied = await api(`/v1/organizations/${owner.organizationId}/notification-channels`, owner, { apiKey: keySecret });
    expect(apiKeyDenied.status).toBe(403);

    const foreign = await createIdentity("owner");
    const crossTenant = await api(`/v1/organizations/${foreign.organizationId}/notification-channels`, owner);
    expect(crossTenant.status).toBe(403);
  });

  it("cancels pending deliveries when a member disables their channel", async () => {
    const member = await createIdentity("member");
    const channel = await createEmailChannel(member);
    const monitorId = await createMonitor(member.organizationId);
    const deliveryId = await queueDelivery(member, monitorId, channel.id);

    const response = await api(`/v1/organizations/${member.organizationId}/notification-channels/${channel.id}`, member, {
      method: "PATCH", body: { enabled: false }
    });
    expect(response.status).toBe(200);
    const row = await env.DB.prepare("SELECT status, last_error_code, lease_token FROM notification_deliveries WHERE id = ?")
      .bind(deliveryId).first<{ status: string; last_error_code: string; lease_token: string | null }>();
    expect(row).toMatchObject({ status: "failed", last_error_code: "CHANNEL_DISABLED", lease_token: null });
  });

  it("enqueues incident lifecycle events from the scheduler finalizer", async () => {
    const owner = await createIdentity("owner");
    await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const times = [
      new Date("2026-11-18T09:00:00.000Z"),
      new Date("2026-11-18T09:05:00.000Z"),
      new Date("2026-11-18T09:10:00.000Z"),
      new Date("2026-11-18T09:15:00.000Z")
    ];

    for (let index = 0; index < times.length; index++) {
      const leaseToken = `notification-lease-${index.toString().padStart(2, "0")}`;
      await env.DB.prepare("UPDATE monitors SET check_lease_token = ?, check_lease_until = ? WHERE id = ?")
        .bind(leaseToken, new Date(times[index].getTime() + 120_000).toISOString(), monitorId).run();
      const isUp = index >= 2;
      const accepted = await finalizeMonitorCheck(env.DB, {
        monitorId,
        leaseToken,
        checkedAt: times[index],
        nextCheckAt: new Date(times[index].getTime() + 300_000),
        isUp,
        statusCode: isUp ? 200 : null,
        responseTimeMs: isUp ? 80 : 0,
        errorCode: isUp ? null : "TIMEOUT",
        failureThreshold: 2,
        recoveryThreshold: 2
      });
      expect(accepted).toBe(true);
    }

    const events = await env.DB.prepare("SELECT event_type FROM notification_deliveries WHERE organization_id = ? ORDER BY event_type")
      .bind(owner.organizationId).all<{ event_type: string }>();
    expect(events.results.map(row => row.event_type).sort()).toEqual(["incident.monitoring", "incident.opened", "incident.resolved"]);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM notification_deliveries WHERE organization_id = ?")
      .bind(owner.organizationId).first<{ count: number }>();
    expect(count?.count).toBe(3);
  });

  it("queues customer-authored incident status changes exactly once", async () => {
    const owner = await createIdentity("owner");
    await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const incident = await createIncident(monitorId);

    const changed = await api(`/v1/incidents/${incident.id}`, owner, {
      method: "PATCH",
      body: { status: "identified", message: "We identified a provider outage.", visibility: "public" }
    });
    expect(changed.status).toBe(200);
    const repeated = await api(`/v1/incidents/${incident.id}`, owner, {
      method: "PATCH", body: { status: "identified" }
    });
    expect(repeated.status).toBe(409);

    const rows = await env.DB.prepare("SELECT event_type, recipient_email FROM notification_deliveries WHERE incident_id = ?")
      .bind(incident.id).all<{ event_type: string; recipient_email: string }>();
    expect(rows.results).toEqual([{ event_type: "incident.status_changed", recipient_email: owner.email }]);
  });

  it("sends a claimed notification once and records the provider message id", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      new Response(JSON.stringify({ id: "re_test_message_123" }), {
        status: 200, headers: { "content-type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);
    try {
      const now = new Date();
      await runScheduled(now);
      const row = await env.DB.prepare("SELECT status, attempt_count, provider_message_id FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; provider_message_id: string }>();
      expect(row).toMatchObject({ status: "sent", attempt_count: 1, provider_message_id: "re_test_message_123" });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      const init = fetchMock.mock.calls[0]?.[1];
      expect((init?.headers as Record<string, string>)["Idempotency-Key"]).toContain("zetuwatch-");
      const body = JSON.parse(String(init?.body)) as { to: string[]; html: string; text: string };
      expect(body.to).toEqual([owner.email]);
      expect(body.html).toContain("Payments API");
      expect(body.html).not.toContain("payments.example.test");
      await runScheduled(new Date(now.getTime() + 60_000));
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("retries rate-limited delivery with the same idempotency key", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response("rate limited", { status: 429, headers: { "retry-after": "60" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "re_after_retry" }), {
        status: 200, headers: { "content-type": "application/json" }
      }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const now = new Date();
      await runScheduled(now);
      const queued = await env.DB.prepare("SELECT status, attempt_count, last_error_code, next_attempt_at FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; last_error_code: string; next_attempt_at: string }>();
      expect(queued?.status).toBe("queued");
      expect(queued?.attempt_count).toBe(1);
      expect(queued?.last_error_code).toBe("PROVIDER_RATE_LIMITED");
      expect(new Date(queued!.next_attempt_at).getTime()).toBeGreaterThan(now.getTime());

      await env.DB.prepare("UPDATE notification_deliveries SET next_attempt_at = ? WHERE id = ?")
        .bind(new Date(now.getTime() - 1000).toISOString(), deliveryId).run();
      await runScheduled(new Date(now.getTime() + 1_000));
      const sent = await env.DB.prepare("SELECT status, attempt_count, provider_message_id FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; provider_message_id: string }>();
      expect(sent).toMatchObject({ status: "sent", attempt_count: 2, provider_message_id: "re_after_retry" });
      const firstKey = (fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>)["Idempotency-Key"];
      const secondKey = (fetchMock.mock.calls[1]?.[1]?.headers as Record<string, string>)["Idempotency-Key"];
      expect(firstKey).toBe(secondKey);
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("does not send the same due delivery from concurrent scheduled invocations", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    await queueDelivery(owner, monitorId, channel.id);
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: "re_concurrent_once" }), {
      status: 200, headers: { "content-type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const now = new Date();
      await Promise.all([runScheduled(now), runScheduled(now)]);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
