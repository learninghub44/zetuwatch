import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import {
  claimDueWebhookDeliveries,
  settleWebhookDelivery
} from "../packages/notifications-core/src/webhook-outbox";

interface Identity {
  userId: string;
  organizationId: string;
  sessionToken: string;
}

async function createIdentity(): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const sessionToken = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionToken));
  const tokenHash = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
  await env.DB.batch([
    env.DB.prepare("INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
      .bind(userId, `${userId}@example.test`, "Webhook outbox test"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Webhook outbox workspace", `webhook-outbox-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'owner')")
      .bind(organizationId, userId),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, tokenHash, new Date(Date.now() + 3_600_000).toISOString())
  ]);
  return { userId, organizationId, sessionToken };
}

async function createEndpoint(identity: Identity): Promise<string> {
  const response = await exports.default.fetch(new Request(
    `https://api.zetuwatch.test/v1/organizations/${identity.organizationId}/webhooks`,
    {
      method: "POST",
      headers: {
        cookie: `zw_session=${identity.sessionToken}`,
        "cf-connecting-ip": crypto.randomUUID(),
        "content-type": "application/json"
      },
      body: JSON.stringify({ name: "Delivery receiver", url: `https://hooks.example.com/${crypto.randomUUID()}` })
    }
  ));
  expect(response.status).toBe(201);
  const payload = await response.json() as { endpoint: { id: string }; deliveryEnabled: boolean };
  expect(payload.deliveryEnabled).toBe(false);
  return payload.endpoint.id;
}

async function enableEndpoint(endpointId: string): Promise<void> {
  await env.DB.prepare("UPDATE webhook_endpoints SET is_enabled = 1 WHERE id = ?")
    .bind(endpointId).run();
}

async function createMonitor(organizationId: string): Promise<string> {
  const monitorId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)")
    .bind(monitorId, organizationId, "Webhook test monitor", "https://service.example.test/health").run();
  return monitorId;
}

async function createIncidentEvent(
  monitorId: string,
  eventType = "incident.opened",
  visibility: "internal" | "public" = "internal",
  createdAt = new Date(Date.now() - 60_000).toISOString()
): Promise<{ incidentId: string; eventId: string }> {
  const incidentId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, 'investigating', ?)")
      .bind(incidentId, monitorId, createdAt, "A real persisted incident fixture"),
    env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at, visibility) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(eventId, incidentId, eventType, "Persisted incident event", createdAt, visibility)
  ]);
  return { incidentId, eventId };
}

describe("durable webhook delivery outbox", () => {
  it("fans out only to enabled endpoints in the incident's own workspace", async () => {
    const first = await createIdentity();
    const second = await createIdentity();
    const firstEndpoint = await createEndpoint(first);
    const secondEndpoint = await createEndpoint(second);
    await enableEndpoint(firstEndpoint);
    await enableEndpoint(secondEndpoint);

    const monitorId = await createMonitor(first.organizationId);
    const event = await createIncidentEvent(monitorId);
    const rows = await env.DB.prepare(`
      SELECT id, organization_id AS organizationId, endpoint_id AS endpointId,
        incident_id AS incidentId, event_id AS eventId, status, attempt_count AS attemptCount
      FROM webhook_deliveries WHERE event_id = ?
    `).bind(event.eventId).all<{
      id: string; organizationId: string; endpointId: string; incidentId: string;
      eventId: string; status: string; attemptCount: number;
    }>();

    expect(rows.results).toHaveLength(1);
    expect(rows.results[0]).toMatchObject({
      organizationId: first.organizationId,
      endpointId: firstEndpoint,
      incidentId: event.incidentId,
      eventId: event.eventId,
      status: "queued",
      attemptCount: 0
    });
    expect(Object.keys(rows.results[0] ?? {})).not.toEqual(expect.arrayContaining([
      "destination_url", "destination_ciphertext", "secret_ciphertext", "secret"
    ]));

    await env.DB.prepare(`
      INSERT OR IGNORE INTO webhook_deliveries
        (id, organization_id, endpoint_id, incident_id, event_id, status, attempt_count, next_attempt_at)
      VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)
    `).bind(
      crypto.randomUUID(), first.organizationId, firstEndpoint,
      event.incidentId, event.eventId, new Date().toISOString()
    ).run();
    const duplicateCount = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM webhook_deliveries WHERE event_id = ? AND endpoint_id = ?"
    ).bind(event.eventId, firstEndpoint).first<{ total: number }>();
    expect(duplicateCount?.total).toBe(1);

    await expect(env.DB.prepare(`
      INSERT INTO webhook_deliveries
        (id, organization_id, endpoint_id, incident_id, event_id, status, attempt_count, next_attempt_at)
      VALUES (?, ?, ?, ?, ?, 'queued', 0, ?)
    `).bind(
      crypto.randomUUID(), first.organizationId, secondEndpoint,
      event.incidentId, event.eventId, new Date().toISOString()
    ).run()).rejects.toThrow("WEBHOOK_DELIVERY_TENANT_MISMATCH");
  });

  it("never queues internal customer notes or internal status changes", async () => {
    const identity = await createIdentity();
    const endpointId = await createEndpoint(identity);
    await enableEndpoint(endpointId);
    const internalNote = await createIncidentEvent(await createMonitor(identity.organizationId), "incident.update", "internal");
    const publicNote = await createIncidentEvent(await createMonitor(identity.organizationId), "incident.update", "public");
    const internalStatus = await createIncidentEvent(await createMonitor(identity.organizationId), "incident.status_changed", "internal");
    const publicStatus = await createIncidentEvent(await createMonitor(identity.organizationId), "incident.status_changed", "public");

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM webhook_deliveries WHERE endpoint_id = ?"
    ).bind(endpointId).first<{ total: number }>();
    expect(count?.total).toBe(2);

    for (const excluded of [internalNote, internalStatus]) {
      const row = await env.DB.prepare(
        "SELECT COUNT(*) AS total FROM webhook_deliveries WHERE event_id = ?"
      ).bind(excluded.eventId).first<{ total: number }>();
      expect(row?.total).toBe(0);
    }
    for (const included of [publicNote, publicStatus]) {
      const row = await env.DB.prepare(
        "SELECT COUNT(*) AS total FROM webhook_deliveries WHERE event_id = ?"
      ).bind(included.eventId).first<{ total: number }>();
      expect(row?.total).toBe(1);
    }
  });

  it("does not enqueue for disabled or soft-deleted endpoints", async () => {
    const identity = await createIdentity();
    const endpointId = await createEndpoint(identity);
    const monitorId = await createMonitor(identity.organizationId);
    const disabledEvent = await createIncidentEvent(monitorId);
    await enableEndpoint(endpointId);
    await env.DB.prepare("UPDATE webhook_endpoints SET is_enabled = 0, deleted_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), endpointId).run();
    const deletedEvent = await createIncidentEvent(await createMonitor(identity.organizationId));

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM webhook_deliveries WHERE endpoint_id = ?"
    ).bind(endpointId).first<{ total: number }>();
    expect(count?.total).toBe(0);
    expect(disabledEvent.eventId).not.toBe(deletedEvent.eventId);
  });

  it("claims with leases, records each attempt and rejects stale settlement", async () => {
    const identity = await createIdentity();
    const endpointId = await createEndpoint(identity);
    await enableEndpoint(endpointId);
    const monitorId = await createMonitor(identity.organizationId);
    const base = new Date(Date.now() - 120_000);
    const event = await createIncidentEvent(monitorId, "incident.opened", "internal", base.toISOString());
    const now = new Date(base.getTime() + 1_000);

    const firstClaim = await claimDueWebhookDeliveries(env.DB, {
      now, leaseMs: 30_000, limit: 1, token: "webhook-claim-token-0001"
    });
    expect(firstClaim).toHaveLength(1);
    expect(firstClaim[0]).toMatchObject({
      organizationId: identity.organizationId,
      endpointId,
      incidentId: event.incidentId,
      eventId: event.eventId,
      attemptCount: 1,
      leaseToken: "webhook-claim-token-0001"
    });

    const overlapping = await claimDueWebhookDeliveries(env.DB, {
      now, leaseMs: 30_000, limit: 1, token: "webhook-claim-token-0002"
    });
    expect(overlapping).toHaveLength(0);

    const retryAt = new Date(now.getTime() + 31_000);
    await expect(settleWebhookDelivery(env.DB, firstClaim[0]!, {
      kind: "retry", errorCode: "REMOTE_UNAVAILABLE", responseStatus: 503,
      now: new Date(now.getTime() + 1_000)
    })).resolves.toBe(true);

    const afterRetry = await env.DB.prepare(
      "SELECT status, next_attempt_at, attempt_count, lease_token FROM webhook_deliveries WHERE event_id = ?"
    ).bind(event.eventId).first<{
      status: string; next_attempt_at: string; attempt_count: number; lease_token: string | null;
    }>();
    expect(afterRetry).toMatchObject({ status: "queued", attempt_count: 1, lease_token: null });
    const dueAt = new Date(afterRetry!.next_attempt_at);
    expect(dueAt.getTime()).toBeLessThanOrEqual(retryAt.getTime() + 1_000);

    const secondClaim = await claimDueWebhookDeliveries(env.DB, {
      now: dueAt, leaseMs: 30_000, limit: 1, token: "webhook-claim-token-0003"
    });
    expect(secondClaim).toHaveLength(1);
    expect(secondClaim[0]?.attemptCount).toBe(2);

    const thirdClaimAt = new Date(new Date(secondClaim[0]!.leaseUntil).getTime() + 1);
    const thirdClaim = await claimDueWebhookDeliveries(env.DB, {
      now: thirdClaimAt, leaseMs: 30_000, limit: 1, token: "webhook-claim-token-0004"
    });
    expect(thirdClaim).toHaveLength(1);
    expect(thirdClaim[0]?.attemptCount).toBe(3);

    await expect(settleWebhookDelivery(env.DB, secondClaim[0]!, {
      kind: "sent", responseStatus: 204, now: new Date(thirdClaimAt.getTime() + 1)
    })).resolves.toBe(false);
    await expect(settleWebhookDelivery(env.DB, thirdClaim[0]!, {
      kind: "sent", responseStatus: 204, now: new Date(thirdClaimAt.getTime() + 2)
    })).resolves.toBe(true);

    const attempts = await env.DB.prepare(`
      SELECT attempt_number AS attemptNumber, status, response_status AS responseStatus, error_code AS errorCode
      FROM webhook_delivery_attempts
      WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = ?)
      ORDER BY attempt_number
    `).bind(event.eventId).all<{
      attemptNumber: number; status: string; responseStatus: number | null; errorCode: string | null;
    }>();
    expect(attempts.results).toEqual([
      { attemptNumber: 1, status: "retry", responseStatus: 503, errorCode: "REMOTE_UNAVAILABLE" },
      { attemptNumber: 2, status: "abandoned", responseStatus: null, errorCode: "LEASE_EXPIRED" },
      { attemptNumber: 3, status: "sent", responseStatus: 204, errorCode: null }
    ]);

    const delivery = await env.DB.prepare(
      "SELECT status, attempt_count AS attemptCount, response_status AS responseStatus, delivered_at AS deliveredAt, next_attempt_at AS nextAttemptAt FROM webhook_deliveries WHERE event_id = ?"
    ).bind(event.eventId).first<{
      status: string; attemptCount: number; responseStatus: number; deliveredAt: string | null; nextAttemptAt: string | null;
    }>();
    expect(delivery).toMatchObject({ status: "sent", attemptCount: 3, responseStatus: 204, nextAttemptAt: null });
    expect(delivery?.deliveredAt).toBeTruthy();

    await expect(env.DB.prepare(
      "UPDATE webhook_delivery_attempts SET error_code = 'TAMPERED' WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = ?)"
    ).bind(event.eventId).run()).rejects.toThrow("WEBHOOK_DELIVERY_ATTEMPTS_IMMUTABLE");
  });
});
