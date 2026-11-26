import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { dispatchWebhookBatch, type WebhookDispatchEnv } from "../packages/notifications-core/src/webhook-dispatch";
import { encryptWebhookValue, createWebhookSecret, WEBHOOK_ENCRYPTION_KEY_VERSION } from "../packages/notifications-core/src/webhook-secrets";
import { verifyWebhookSignature } from "../packages/notifications-core/src/webhook-signing";

const encryptionKey = (env as typeof env & { WEBHOOK_ENCRYPTION_KEY: string }).WEBHOOK_ENCRYPTION_KEY;
const agentSecret = "test-only-agent-shared-secret-with-32-bytes";

interface Identity {
  userId: string;
  organizationId: string;
}

async function createIdentity(): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
      .bind(userId, `${userId}@example.test`, "Webhook dispatch test"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Dispatch workspace", `dispatch-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'owner')")
      .bind(organizationId, userId)
  ]);
  return { userId, organizationId };
}

async function createEndpoint(identity: Identity): Promise<{ id: string; secret: string }> {
  const id = crypto.randomUUID();
  const destinationUrl = `https://hooks.customer.example.com/${id}`;
  const secret = createWebhookSecret();
  const context = `zetuwatch:webhook:v${WEBHOOK_ENCRYPTION_KEY_VERSION}:${identity.organizationId}:${id}`;
  const [encryptedUrl, encryptedSecret] = await Promise.all([
    encryptWebhookValue(destinationUrl, encryptionKey, context + ":url"),
    encryptWebhookValue(secret, encryptionKey, context + ":secret")
  ]);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(destinationUrl));
  const destinationHash = Array.from(new Uint8Array(digest), value => value.toString(16).padStart(2, "0")).join("");
  await env.DB.prepare(`
    INSERT INTO webhook_endpoints (
      id, organization_id, name, destination_host, destination_hash,
      destination_ciphertext, destination_nonce, secret_ciphertext, secret_nonce,
      secret_last4, encryption_key_version, is_enabled, created_by
    ) VALUES (?, ?, 'Dispatch receiver', 'hooks.customer.example.com', ?, ?, ?, ?, ?, ?, ?, 1, ?)
  `).bind(
    id, identity.organizationId, destinationHash,
    encryptedUrl.ciphertext, encryptedUrl.nonce,
    encryptedSecret.ciphertext, encryptedSecret.nonce,
    secret.slice(-4), WEBHOOK_ENCRYPTION_KEY_VERSION, identity.userId
  ).run();
  return { id, secret };
}

async function createIncidentEvent(
  identity: Identity,
  options: { eventType?: string; visibility?: "internal" | "public"; message?: string } = {}
): Promise<{ incidentId: string; eventId: string }> {
  const monitorId = crypto.randomUUID();
  const incidentId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const createdAt = new Date(Date.now() - 60_000).toISOString();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)")
      .bind(monitorId, identity.organizationId, "Checkout API", "https://api.example.com/health"),
    env.DB.prepare("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, 'investigating', ?)")
      .bind(incidentId, monitorId, createdAt, "Internal incident summary"),
    env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at, visibility) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(
        eventId, incidentId, options.eventType ?? "incident.opened",
        options.message ?? "Internal diagnostic detail",
        createdAt, options.visibility ?? "internal"
      )
  ]);
  return { incidentId, eventId };
}

function dispatchEnv(): WebhookDispatchEnv {
  return {
    DB: env.DB,
    WEBHOOKS_ENABLED: "true",
    WEBHOOK_ENCRYPTION_KEY: encryptionKey,
    PROBE_AGENT_URL: "https://agent.example.test/v1/probe",
    PROBE_SHARED_SECRET: agentSecret
  };
}

describe("scheduled webhook dispatcher", () => {
  it("sends an exact-body signed event and stores a successful attempt without leaking internal details", async () => {
    const identity = await createIdentity();
    const endpoint = await createEndpoint(identity);
    const event = await createIncidentEvent(identity);
    const now = new Date();

    const captured: { job?: { destinationUrl: string; eventId: string; payload: string; signatureHeader: string } } = {};
    const summary = await dispatchWebhookBatch(dispatchEnv(), {
      now,
      clock: () => new Date(now.getTime() + 1_000),
      sender: async (_agentUrl, _agentSecret, job) => {
        captured.job = job;
        return { delivered: true, responseStatus: 204, errorCode: null, retryAfterSeconds: null };
      }
    });

    expect(summary).toMatchObject({ skipped: false, claimed: 1, sent: 1, retried: 0, failed: 0, stale: 0 });
    expect(captured.job).toBeDefined();
    const sentJob = captured.job!;
    expect(sentJob.destinationUrl).toContain("hooks.customer.example.com");
    expect(sentJob.eventId).toBe(event.eventId);
    const payload = JSON.parse(sentJob.payload) as Record<string, unknown>;
    expect(payload).toMatchObject({
      eventId: event.eventId,
      type: "incident.opened",
      data: {
        workspace: { name: "Dispatch workspace" },
        monitor: { name: "Checkout API" },
        incident: { id: event.incidentId, status: "investigating" }
      }
    });
    expect(sentJob.payload).not.toContain("Internal diagnostic detail");
    expect(sentJob.payload).not.toContain("Internal incident summary");
    expect(sentJob.payload).not.toContain("https://api.example.com");
    await expect(verifyWebhookSignature(
      endpoint.secret,
      sentJob.payload,
      sentJob.signatureHeader,
      Math.floor((now.getTime() + 1_000) / 1000)
    )).resolves.toBe(true);

    const delivery = await env.DB.prepare(
      "SELECT status, response_status AS responseStatus, attempt_count AS attemptCount FROM webhook_deliveries WHERE event_id = ?"
    ).bind(event.eventId).first<{ status: string; responseStatus: number; attemptCount: number }>();
    expect(delivery).toEqual({ status: "sent", responseStatus: 204, attemptCount: 1 });
    const attempt = await env.DB.prepare(
      "SELECT status, response_status AS responseStatus, error_code AS errorCode FROM webhook_delivery_attempts WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = ?)"
    ).bind(event.eventId).first<{ status: string; responseStatus: number; errorCode: string | null }>();
    expect(attempt).toEqual({ status: "sent", responseStatus: 204, errorCode: null });
  });

  it("includes only explicitly public incident update text", async () => {
    const identity = await createIdentity();
    await createEndpoint(identity);
    const event = await createIncidentEvent(identity, {
      eventType: "incident.update",
      visibility: "public",
      message: "We have identified the issue and are applying a fix."
    });
    const now = new Date();
    let payloadText = "";
    const summary = await dispatchWebhookBatch(dispatchEnv(), {
      now,
      clock: () => new Date(now.getTime() + 1_000),
      sender: async (_agentUrl, _agentSecret, job) => {
        payloadText = job.payload;
        return { delivered: true, responseStatus: 200, errorCode: null, retryAfterSeconds: null };
      }
    });
    expect(summary.sent).toBe(1);
    expect(payloadText).toContain("We have identified the issue");
    expect(JSON.parse(payloadText)).toMatchObject({ eventId: event.eventId, type: "incident.update" });
  });

  it("schedules bounded retries for transient receiver failures", async () => {
    const identity = await createIdentity();
    await createEndpoint(identity);
    const event = await createIncidentEvent(identity);
    const now = new Date();
    const summary = await dispatchWebhookBatch(dispatchEnv(), {
      now,
      clock: () => new Date(now.getTime() + 1_000),
      sender: async () => ({
        delivered: false, responseStatus: 503, errorCode: "REMOTE_SERVER_ERROR", retryAfterSeconds: 90
      })
    });
    expect(summary).toMatchObject({ claimed: 1, retried: 1, failed: 0 });
    const row = await env.DB.prepare(
      "SELECT status, attempt_count AS attemptCount, last_error_code AS lastErrorCode, next_attempt_at AS nextAttemptAt FROM webhook_deliveries WHERE event_id = ?"
    ).bind(event.eventId).first<{ status: string; attemptCount: number; lastErrorCode: string; nextAttemptAt: string }>();
    expect(row).toMatchObject({ status: "queued", attemptCount: 1, lastErrorCode: "REMOTE_SERVER_ERROR" });
    expect(new Date(row!.nextAttemptAt).getTime()).toBeGreaterThan(now.getTime());
  });

  it("cancels an in-flight delivery when an owner disables its endpoint during the request", async () => {
    const identity = await createIdentity();
    const endpoint = await createEndpoint(identity);
    const event = await createIncidentEvent(identity);
    const now = new Date();
    const summary = await dispatchWebhookBatch(dispatchEnv(), {
      now,
      clock: () => new Date(now.getTime() + 1_000),
      sender: async () => {
        await env.DB.prepare("UPDATE webhook_endpoints SET is_enabled = 0 WHERE id = ?").bind(endpoint.id).run();
        return { delivered: true, responseStatus: 204, errorCode: null, retryAfterSeconds: null };
      }
    });
    expect(summary).toMatchObject({ claimed: 1, sent: 0, stale: 1 });
    const row = await env.DB.prepare(
      "SELECT status, lease_token AS leaseToken FROM webhook_deliveries WHERE event_id = ?"
    ).bind(event.eventId).first<{ status: string; leaseToken: string | null }>();
    expect(row).toEqual({ status: "cancelled", leaseToken: null });
  });

  it("does not claim or mutate deliveries when the operator has not explicitly enabled webhooks", async () => {
    const identity = await createIdentity();
    const endpoint = await createEndpoint(identity);
    await createIncidentEvent(identity);
    const disabled = { ...dispatchEnv(), WEBHOOKS_ENABLED: "false" };
    const summary = await dispatchWebhookBatch(disabled);
    expect(summary).toMatchObject({ skipped: true, reason: "WEBHOOKS_DISABLED", claimed: 0 });
    const row = await env.DB.prepare(
      "SELECT status, attempt_count AS attemptCount FROM webhook_deliveries WHERE endpoint_id = ?"
    ).bind(endpoint.id).first<{ status: string; attemptCount: number }>();
    expect(row).toEqual({ status: "queued", attemptCount: 0 });
  });
});
