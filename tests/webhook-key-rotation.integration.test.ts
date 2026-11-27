import { env } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { encryptWebhookValue, decryptWebhookValue, createWebhookSecret } from "../packages/notifications-core/src/webhook-secrets";
import { rotateWebhookEncryptionBatch, type WebhookKeyRotationEnv } from "../packages/notifications-core/src/webhook-key-rotation";
import { webhookEncryptionContext } from "../packages/notifications-core/src/webhook-keyring";

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
