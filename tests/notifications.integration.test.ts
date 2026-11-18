import { env, exports } from "cloudflare:workers";
import { describe, expect, it, vi } from "vitest";
import { finalizeMonitorCheck } from "../packages/scheduler-core/src/claims";
import { claimDueNotificationDeliveries, settleNotificationDelivery } from "../packages/notifications-core/src/outbox";
import { dispatchNotificationBatch } from "../packages/notifications-core/src/dispatch";

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
     next_attempt_at, event_id, event_type, recipient_email, channel_created_by)
    VALUES (?, ?, ?, ?, 'resend', 'queued', 0, ?, ?, 'incident.opened', ?, ?)`)
    .bind(deliveryId, identity.organizationId, incident.id, channelId,
      new Date(Date.now() - 1000).toISOString(), incident.eventId, identity.email, identity.userId).run();
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

  it("never enqueues or dispatches internal incident notes or status changes", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const incident = await createIncident(monitorId);

    const statusChanged = await api(`/v1/incidents/${incident.id}`, owner, {
      method: "PATCH",
      body: { status: "identified" }
    });
    expect(statusChanged.status).toBe(200);
    const statusEvent = await env.DB.prepare(
      "SELECT id, visibility FROM incident_events WHERE incident_id = ? AND event_type = 'incident.status_changed' ORDER BY created_at DESC LIMIT 1"
    ).bind(incident.id).first<{ id: string; visibility: string }>();
    expect(statusEvent?.visibility).toBe("internal");
    const statusDeliveryCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM notification_deliveries WHERE event_id = ?"
    ).bind(statusEvent!.id).first<{ count: number }>();
    expect(statusDeliveryCount?.count).toBe(0);

    const internalResponse = await api(`/v1/incidents/${incident.id}/updates`, owner, {
      method: "POST",
      body: { message: "Internal operator note must never be emailed.", visibility: "internal" }
    });
    expect(internalResponse.status).toBe(201);
    const internalPayload = await internalResponse.json() as { eventId: string };
    const internalDeliveryCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM notification_deliveries WHERE event_id = ?"
    ).bind(internalPayload.eventId).first<{ count: number }>();
    expect(internalDeliveryCount?.count).toBe(0);

    const publicResponse = await api(`/v1/incidents/${incident.id}/updates`, owner, {
      method: "POST",
      body: { message: "Public update should be emailed.", visibility: "public" }
    });
    expect(publicResponse.status).toBe(201);
    const publicPayload = await publicResponse.json() as { eventId: string };
    const publicDelivery = await env.DB.prepare(
      "SELECT id FROM notification_deliveries WHERE event_id = ? AND channel_id = ?"
    ).bind(publicPayload.eventId, channel.id).first<{ id: string }>();
    expect(publicDelivery?.id).toBeTruthy();

    // Simulate an older or manually inserted outbox row to prove the dispatcher
    // independently rechecks visibility before contacting the email provider.
    const legacyInternalDeliveryId = crypto.randomUUID();
    await env.DB.prepare(`INSERT INTO notification_deliveries
      (id, organization_id, incident_id, channel_id, provider, status, attempt_count,
       next_attempt_at, event_id, event_type, recipient_email, channel_created_by)
      VALUES (?, ?, ?, ?, 'resend', 'queued', 0, ?, ?, 'incident.update', ?, ?)`)
      .bind(
        legacyInternalDeliveryId,
        owner.organizationId,
        incident.id,
        channel.id,
        new Date(Date.now() - 1_000).toISOString(),
        internalPayload.eventId,
        owner.email,
        owner.userId
      ).run();

    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: "re_public_update_only" }), {
      status: 200,
      headers: { "content-type": "application/json" }
    }));
    const summary = await dispatchNotificationBatch({
      DB: env.DB,
      PUBLIC_APP_URL: "https://app.zetuwatch.test",
      RESEND_API_KEY: "re_test_only",
      EMAIL_FROM: "ZetuWatch <alerts@example.test>"
    }, {
      limit: 5,
      fetcher: fetchMock as unknown as typeof fetch
    });

    expect(summary).toMatchObject({ claimed: 2, sent: 1, failed: 1 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const internalRow = await env.DB.prepare(
      "SELECT status, last_error_code FROM notification_deliveries WHERE id = ?"
    ).bind(legacyInternalDeliveryId).first<{ status: string; last_error_code: string }>();
    expect(internalRow).toMatchObject({ status: "failed", last_error_code: "RECIPIENT_NOT_ELIGIBLE" });
    const publicRow = await env.DB.prepare(
      "SELECT status FROM notification_deliveries WHERE id = ?"
    ).bind(publicDelivery.id).first<{ status: string }>();
    expect(publicRow?.status).toBe("sent");

    const requestInit = fetchMock.mock.calls[0]?.[1] as RequestInit | undefined;
    const emailBody = JSON.parse(String(requestInit?.body)) as { html: string; text: string };
    expect(emailBody.html).toContain("Public update should be emailed.");
    expect(emailBody.html).not.toContain("Internal operator note must never be emailed.");
    expect(emailBody.text).not.toContain("Internal operator note must never be emailed.");
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

 
describe("notification outbox lease safety", () => {
  it("rejects expired claims and allows only the replacement lease to settle", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);
    const now = new Date(Date.now() + 2_000);

    const first = await claimDueNotificationDeliveries(env.DB, {
      now,
      leaseMs: 30_000,
      token: "notification-lease-first-0001"
    });
    expect(first).toHaveLength(1);
    expect(first[0]?.id).toBe(deliveryId);

    const expiredAt = new Date(now.getTime() + 30_001);
    const expiredSettlement = await settleNotificationDelivery(env.DB, first[0]!, {
      kind: "sent",
      providerMessageId: "stale-provider-message",
      now: expiredAt
    });
    expect(expiredSettlement).toBe(false);

    const replacement = await claimDueNotificationDeliveries(env.DB, {
      now: expiredAt,
      leaseMs: 30_000,
      token: "notification-lease-second-0002"
    });
    expect(replacement).toHaveLength(1);
    expect(replacement[0]?.attemptCount).toBe(2);

    const staleAfterReclaim = await settleNotificationDelivery(env.DB, first[0]!, {
      kind: "sent",
      providerMessageId: "stale-provider-message",
      now: new Date(expiredAt.getTime() + 1)
    });
    expect(staleAfterReclaim).toBe(false);

    const currentSettlement = await settleNotificationDelivery(env.DB, replacement[0]!, {
      kind: "sent",
      providerMessageId: "current-provider-message",
      now: new Date(expiredAt.getTime() + 1)
    });
    expect(currentSettlement).toBe(true);

    const row = await env.DB.prepare("SELECT status, attempt_count, provider_message_id FROM notification_deliveries WHERE id = ?")
      .bind(deliveryId).first<{ status: string; attempt_count: number; provider_message_id: string }>();
    expect(row).toMatchObject({
      status: "sent",
      attempt_count: 2,
      provider_message_id: "current-provider-message"
    });
  });
});

describe("Resend idempotency conflict handling", () => {
  it("retries concurrent idempotent requests with the same stable key", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        name: "concurrent_idempotent_requests",
        message: "Another request with this key is still processing."
      }), { status: 409, headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: "re_concurrent_retry" }), {
        status: 200, headers: { "content-type": "application/json" }
      }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      const now = new Date();
      await runScheduled(now);
      const queued = await env.DB.prepare("SELECT status, attempt_count, last_error_code FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; last_error_code: string }>();
      expect(queued).toMatchObject({
        status: "queued",
        attempt_count: 1,
        last_error_code: "PROVIDER_REQUEST_IN_PROGRESS"
      });

      await env.DB.prepare("UPDATE notification_deliveries SET next_attempt_at = ? WHERE id = ?")
        .bind(new Date(now.getTime() - 1_000).toISOString(), deliveryId).run();
      await runScheduled(new Date(now.getTime() + 1_000));

      const sent = await env.DB.prepare("SELECT status, attempt_count, provider_message_id FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; provider_message_id: string }>();
      expect(sent).toMatchObject({
        status: "sent",
        attempt_count: 2,
        provider_message_id: "re_concurrent_retry"
      });
      const firstKey = (fetchMock.mock.calls[0]?.[1]?.headers as Record<string, string>)["Idempotency-Key"];
      const secondKey = (fetchMock.mock.calls[1]?.[1]?.headers as Record<string, string>)["Idempotency-Key"];
      expect(firstKey).toBe(secondKey);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

describe("notification delivery log access", () => {
  it("returns only the current workspace delivery records", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);

    const own = await api("/v1/organizations/" + owner.organizationId + "/notification-deliveries", owner);
    expect(own.status).toBe(200);
    const ownPayload = await own.json() as { deliveries: Array<{ id: string; recipientEmail: string; monitorName: string }> };
    expect(ownPayload.deliveries).toEqual([
      expect.objectContaining({
        id: deliveryId,
        recipientEmail: owner.email,
        monitorName: "Payments API"
      })
    ]);

    const foreign = await createIdentity("owner");
    const denied = await api("/v1/organizations/" + owner.organizationId + "/notification-deliveries", foreign);
    expect(denied.status).toBe(403);
  });
});


describe("notification scheduler lag handling", () => {
  it("uses invocation time when a Cron event arrives after its scheduled timestamp", async () => {
    const owner = await createIdentity("owner");
    const channel = await createEmailChannel(owner);
    const monitorId = await createMonitor(owner.organizationId);
    const deliveryId = await queueDelivery(owner, monitorId, channel.id);
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ id: "re_delayed_cron" }), {
      status: 200,
      headers: { "content-type": "application/json" }
    }));
    vi.stubGlobal("fetch", fetchMock);
    try {
      await runScheduled(new Date(Date.now() - 120_000));
      const row = await env.DB.prepare("SELECT status, attempt_count, provider_message_id FROM notification_deliveries WHERE id = ?")
        .bind(deliveryId).first<{ status: string; attempt_count: number; provider_message_id: string }>();
      expect(row).toMatchObject({
        status: "sent",
        attempt_count: 1,
        provider_message_id: "re_delayed_cron"
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});


describe("notification delivery history retention", () => {
  it("keeps a member's delivery history visible after their channel is removed", async () => {
    const member = await createIdentity("member");
    const channel = await createEmailChannel(member);
    const monitorId = await createMonitor(member.organizationId);
    const deliveryId = await queueDelivery(member, monitorId, channel.id);

    const removed = await api("/v1/organizations/" + member.organizationId + "/notification-channels/" + channel.id, member, {
      method: "DELETE"
    });
    expect(removed.status).toBe(200);

    const stored = await env.DB.prepare("SELECT status, channel_id, channel_created_by FROM notification_deliveries WHERE id = ?")
      .bind(deliveryId).first<{ status: string; channel_id: string | null; channel_created_by: string }>();
    expect(stored).toMatchObject({
      status: "failed",
      channel_id: null,
      channel_created_by: member.userId
    });

    const history = await api("/v1/organizations/" + member.organizationId + "/notification-deliveries", member);
    expect(history.status).toBe(200);
    const payload = await history.json() as { deliveries: Array<{ id: string; lastErrorCode: string }> };
    expect(payload.deliveries).toEqual([
      expect.objectContaining({ id: deliveryId, lastErrorCode: "CHANNEL_REMOVED" })
    ]);
  });
});
