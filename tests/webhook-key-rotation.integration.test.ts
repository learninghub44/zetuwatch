import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { encryptWebhookValue, decryptWebhookValue, createWebhookSecret } from "../packages/notifications-core/src/webhook-secrets";
import { rotateWebhookEncryptionBatch, type WebhookKeyRotationEnv } from "../packages/notifications-core/src/webhook-key-rotation";
import { webhookEncryptionContext } from "../packages/notifications-core/src/webhook-keyring";
import { dispatchWebhookBatch, type WebhookDispatchEnv } from "../packages/notifications-core/src/webhook-dispatch";

const KEY_V1 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const KEY_V2 = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const WRONG_KEY = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC";

interface Identity {
  userId: string;
  organizationId: string;
}

interface Endpoint {
  id: string;
  destination: string;
  secret: string;
}

async function createIdentity(): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
      .bind(userId, `${userId}@example.test`, "Key rotation test"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Rotation workspace", `rotation-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'owner')")
      .bind(organizationId, userId)
  ]);
  return { userId, organizationId };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function createLegacyEndpoint(identity: Identity): Promise<Endpoint> {
  const id = crypto.randomUUID();
  const destination = `https://hooks.rotation.example.com/${id}`;
  const secret = createWebhookSecret();
  const urlContext = webhookEncryptionContext(1, "v1", identity.organizationId, id, "url");
  const secretContext = webhookEncryptionContext(1, "v1", identity.organizationId, id, "secret");
  const [urlCipher, secretCipher] = await Promise.all([
    encryptWebhookValue(destination, KEY_V1, urlContext),
    encryptWebhookValue(secret, KEY_V1, secretContext)
  ]);
  await env.DB.prepare(`
    INSERT INTO webhook_endpoints (
      id, organization_id, name, destination_host, destination_hash,
      destination_ciphertext, destination_nonce, secret_ciphertext, secret_nonce,
      secret_last4, encryption_key_version, is_enabled, created_by
    ) VALUES (?, ?, 'Rotation receiver', 'hooks.rotation.example.com', ?, ?, ?, ?, ?, ?, 1, 0, ?)
  `).bind(
    id, identity.organizationId, await sha256Hex(destination),
    urlCipher.ciphertext, urlCipher.nonce, secretCipher.ciphertext, secretCipher.nonce,
    secret.slice(-4), identity.userId
  ).run();
  return { id, destination, secret };
}

function rotationEnv(overrides: Partial<WebhookKeyRotationEnv> = {}): WebhookKeyRotationEnv {
  return {
    DB: env.DB,
    WEBHOOK_ENCRYPTION_KEY: KEY_V2,
    WEBHOOK_ENCRYPTION_KEY_ID: "v2",
    WEBHOOK_ENCRYPTION_KEY_PREVIOUS: KEY_V1,
    WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: "v1",
    ...overrides
  };
}

async function createIncidentEvent(identity: Identity, endpointId: string): Promise<string> {
  const monitorId = crypto.randomUUID();
  const incidentId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  const createdAt = new Date(Date.now() - 60_000).toISOString();
  await env.DB.batch([
    env.DB.prepare("UPDATE webhook_endpoints SET is_enabled = 1 WHERE id = ? AND organization_id = ?")
      .bind(endpointId, identity.organizationId),
    env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)")
      .bind(monitorId, identity.organizationId, "Rotation API", "https://api.example.com/health"),
    env.DB.prepare("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, 'investigating', ?)")
      .bind(incidentId, monitorId, createdAt, "Private incident summary"),
    env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at, visibility) VALUES (?, ?, 'incident.opened', ?, ?, 'internal')")
      .bind(eventId, incidentId, "Private diagnostic", createdAt)
  ]);
  return eventId;
}

function dispatchEnv(): WebhookDispatchEnv {
  return {
    DB: env.DB,
    WEBHOOKS_ENABLED: "true",
    WEBHOOK_ENCRYPTION_KEY: KEY_V2,
    WEBHOOK_ENCRYPTION_KEY_ID: "v2",
    WEBHOOK_ENCRYPTION_KEY_PREVIOUS: KEY_V1,
    WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: "v1",
    PROBE_AGENT_URL: "https://agent.example.test/v1/probe",
    PROBE_SHARED_SECRET: "test-only-agent-shared-secret-with-32-bytes"
  };
}

describe("webhook master-key rotation", () => {
  it("re-encrypts both endpoint values and preserves the URL, signing secret and suffix", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    const before = await env.DB.prepare(
      "SELECT destination_ciphertext, secret_ciphertext FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ destination_ciphertext: string; secret_ciphertext: string }>();

    const result = await rotateWebhookEncryptionBatch(rotationEnv(), {
      now: new Date("2026-11-27T06:00:00.000Z")
    });
    expect(result).toMatchObject({ skipped: false, scanned: 1, rotated: 1, failed: 0, conflicts: 0, remaining: 0, blocked: 0 });

    const stored = await env.DB.prepare(`
      SELECT destination_ciphertext AS destinationCiphertext,
        destination_nonce AS destinationNonce,
        secret_ciphertext AS secretCiphertext,
        secret_nonce AS secretNonce,
        secret_last4 AS secretLast4,
        encryption_key_id AS encryptionKeyId
      FROM webhook_endpoints WHERE id = ? AND organization_id = ?
    `).bind(endpoint.id, identity.organizationId).first<{
      destinationCiphertext: string; destinationNonce: string;
      secretCiphertext: string; secretNonce: string; secretLast4: string; encryptionKeyId: string;
    }>();
    expect(stored?.encryptionKeyId).toBe("v2");
    expect(stored?.destinationCiphertext).not.toBe(before?.destination_ciphertext);
    expect(stored?.secretCiphertext).not.toBe(before?.secret_ciphertext);
    expect(stored?.secretLast4).toBe(endpoint.secret.slice(-4));

    const [destination, secret] = await Promise.all([
      decryptWebhookValue({
        ciphertext: stored!.destinationCiphertext, nonce: stored!.destinationNonce
      }, KEY_V2, webhookEncryptionContext(1, "v2", identity.organizationId, endpoint.id, "url")),
      decryptWebhookValue({
        ciphertext: stored!.secretCiphertext, nonce: stored!.secretNonce
      }, KEY_V2, webhookEncryptionContext(1, "v2", identity.organizationId, endpoint.id, "secret"))
    ]);
    expect(destination).toBe(endpoint.destination);
    expect(secret).toBe(endpoint.secret);
    await expect(decryptWebhookValue({
      ciphertext: stored!.destinationCiphertext, nonce: stored!.destinationNonce
    }, KEY_V1, webhookEncryptionContext(1, "v2", identity.organizationId, endpoint.id, "url")))
      .rejects.toThrow("WEBHOOK_DECRYPT_FAILED");
  });

  it("resumes across bounded batches and reports when the previous key can be removed", async () => {
    const identity = await createIdentity();
    await createLegacyEndpoint(identity);
    await createLegacyEndpoint(identity);

    const first = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 });
    expect(first).toMatchObject({ scanned: 1, rotated: 1, remaining: 1, blocked: 0 });
    const second = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 });
    expect(second).toMatchObject({ scanned: 1, rotated: 1, remaining: 0, blocked: 0 });

    const retired = await rotateWebhookEncryptionBatch(rotationEnv({
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: undefined,
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: undefined
    }));
    expect(retired).toMatchObject({ skipped: true, reason: "PREVIOUS_KEY_NOT_CONFIGURED" });
  });

  it("does not overwrite a concurrently rotated endpoint when two batches race", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    const [first, second] = await Promise.all([
      rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 }),
      rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 })
    ]);
    const row = await env.DB.prepare(
      "SELECT encryption_key_id AS keyId FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ keyId: string }>();
    expect(row?.keyId).toBe("v2");
    expect(first.rotated + second.rotated).toBe(1);
    expect(first.failed + second.failed).toBe(0);
  });

  it("leaves authenticated or hash-mismatched ciphertext untouched", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    await env.DB.prepare("UPDATE webhook_endpoints SET destination_hash = ? WHERE id = ?")
      .bind("f".repeat(64), endpoint.id).run();
    const before = await env.DB.prepare(
      "SELECT destination_ciphertext AS value FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ value: string }>();

    const result = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 });
    const after = await env.DB.prepare(
      "SELECT destination_ciphertext AS value, encryption_key_id AS keyId FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ value: string; keyId: string }>();
    expect(result.failed).toBe(1);
    expect(after).toEqual({ value: before?.value, keyId: "v1" });
  });

  it("does not guess when an endpoint references an unknown key id", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    await env.DB.prepare("UPDATE webhook_endpoints SET encryption_key_id = 'orphan-v9' WHERE id = ?")
      .bind(endpoint.id).run();

    const result = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 });
    expect(result).toMatchObject({ scanned: 0, rotated: 0, remaining: 1, blocked: 1 });
    const row = await env.DB.prepare(
      "SELECT encryption_key_id AS keyId FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ keyId: string }>();
    expect(row?.keyId).toBe("orphan-v9");
  });

  it("continues delivering legacy endpoints through the previous key during rotation", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    const eventId = await createIncidentEvent(identity, endpoint.id);
    const result = await dispatchWebhookBatch(dispatchEnv(), {
      sender: async (_url, _secret, job) => {
        expect(job.destinationUrl).toBe(endpoint.destination);
        expect(job.eventId).toBe(eventId);
        return { delivered: true, responseStatus: 204, errorCode: null, retryAfterSeconds: null };
      }
    });
    expect(result).toMatchObject({ skipped: false, claimed: 1, sent: 1, failed: 0 });
  });

  it("delivers a re-encrypted endpoint using only the new current key", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    const rotated = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1 });
    expect(rotated.rotated).toBe(1);
    const eventId = await createIncidentEvent(identity, endpoint.id);
    const currentOnly: WebhookDispatchEnv = {
      ...dispatchEnv(),
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: undefined,
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID: undefined
    };
    const result = await dispatchWebhookBatch(currentOnly, {
      sender: async (_url, _secret, job) => {
        expect(job.destinationUrl).toBe(endpoint.destination);
        expect(job.eventId).toBe(eventId);
        return { delivered: true, responseStatus: 202, errorCode: null, retryAfterSeconds: null };
      }
    });
    expect(result).toMatchObject({ skipped: false, claimed: 1, sent: 1, failed: 0 });
  });

  it("quarantines a bad oldest row so later endpoints still rotate and retries it with backoff", async () => {
    const identity = await createIdentity();
    const firstEndpoint = await createLegacyEndpoint(identity);
    const secondEndpoint = await createLegacyEndpoint(identity);
    const oldest = await env.DB.prepare(`
      SELECT id FROM webhook_endpoints
      WHERE organization_id = ? AND deleted_at IS NULL
      ORDER BY created_at ASC, id ASC LIMIT 1
    `).bind(identity.organizationId).first<{ id: string }>();
    expect(oldest).toBeTruthy();
    await env.DB.prepare("UPDATE webhook_endpoints SET destination_hash = ? WHERE id = ?")
      .bind("f".repeat(64), oldest!.id).run();

    const now = new Date("2026-11-28T06:00:00.000Z");
    const failed = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1, now });
    expect(failed).toMatchObject({ scanned: 1, rotated: 0, failed: 1, remaining: 2 });

    const quarantined = await env.DB.prepare(`
      SELECT attempts, retry_after AS retryAfter, last_error_code AS errorCode
      FROM webhook_key_rotation_failures WHERE endpoint_id = ?
    `).bind(oldest!.id).first<{ attempts: number; retryAfter: string; errorCode: string }>();
    expect(quarantined).toMatchObject({
      attempts: 1,
      retryAfter: new Date(now.getTime() + 60 * 60 * 1_000).toISOString(),
      errorCode: "WEBHOOK_ENDPOINT_AUTHENTICATION_FAILED"
    });

    const next = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1, now });
    expect(next).toMatchObject({ scanned: 1, rotated: 1, failed: 0, remaining: 1 });
    const healthyId = oldest!.id === firstEndpoint.id ? secondEndpoint.id : firstEndpoint.id;
    const healthy = await env.DB.prepare(
      "SELECT encryption_key_id AS keyId FROM webhook_endpoints WHERE id = ?"
    ).bind(healthyId).first<{ keyId: string }>();
    expect(healthy?.keyId).toBe("v2");

    const noDueRows = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1, now });
    expect(noDueRows).toMatchObject({ scanned: 0, rotated: 0, failed: 0, remaining: 1 });

    const retryNow = new Date(now.getTime() + 60 * 60 * 1_000);
    const retried = await rotateWebhookEncryptionBatch(rotationEnv(), { limit: 1, now: retryNow });
    expect(retried).toMatchObject({ scanned: 1, rotated: 0, failed: 1, remaining: 1 });
    const retriedFailure = await env.DB.prepare(
      "SELECT attempts, retry_after AS retryAfter FROM webhook_key_rotation_failures WHERE endpoint_id = ?"
    ).bind(oldest!.id).first<{ attempts: number; retryAfter: string }>();
    expect(retriedFailure).toMatchObject({
      attempts: 2,
      retryAfter: new Date(retryNow.getTime() + 2 * 60 * 60 * 1_000).toISOString()
    });
  });

  it("fails closed when the configured previous key cannot authenticate a row", async () => {
    const identity = await createIdentity();
    const endpoint = await createLegacyEndpoint(identity);
    const result = await rotateWebhookEncryptionBatch(rotationEnv({
      WEBHOOK_ENCRYPTION_KEY_PREVIOUS: WRONG_KEY
    }), { limit: 1 });
    const row = await env.DB.prepare(
      "SELECT encryption_key_id AS keyId FROM webhook_endpoints WHERE id = ?"
    ).bind(endpoint.id).first<{ keyId: string }>();
    expect(result.failed).toBe(1);
    expect(row?.keyId).toBe("v1");
  });
});
