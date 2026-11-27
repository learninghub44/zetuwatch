import {
  decryptWebhookValue,
  encryptWebhookValue,
  normalizeWebhookDestination
} from "./webhook-secrets";
import {
  readWebhookKeyring,
  webhookEncryptionContext,
  type WebhookKeyringEnvironment
} from "./webhook-keyring";

export interface WebhookKeyRotationEnv extends WebhookKeyringEnvironment {
  DB: D1Database;
}

export interface WebhookKeyRotationSummary {
  skipped: boolean;
  reason?: "WEBHOOK_ENCRYPTION_KEY_MISSING" | "WEBHOOK_ENCRYPTION_KEY_INVALID" |
    "WEBHOOK_ENCRYPTION_KEY_ID_INVALID" | "WEBHOOK_ENCRYPTION_KEY_PREVIOUS_INVALID" |
    "WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID_INVALID" | "WEBHOOK_ENCRYPTION_KEY_IDS_MUST_DIFFER" |
    "WEBHOOK_PREVIOUS_KEY_ID_WITHOUT_KEY" | "PREVIOUS_KEY_NOT_CONFIGURED";
  scanned: number;
  rotated: number;
  conflicts: number;
  failed: number;
  remaining: number;
  blocked: number;
  currentKeyId?: string;
  previousKeyId?: string;
}

interface EndpointRow {
  id: string;
  organizationId: string;
  destinationHash: string;
  destinationCiphertext: string;
  destinationNonce: string;
  secretCiphertext: string;
  secretNonce: string;
  secretLast4: string;
  encryptionKeyVersion: number;
  encryptionKeyId: string;
}

const DEFAULT_BATCH_LIMIT = 1;
const MAX_BATCH_LIMIT = 3;
const SECRET_PATTERN = /^whsec_[A-Za-z0-9_-]{43}$/;

function emptySummary(
  reason?: WebhookKeyRotationSummary["reason"],
  currentKeyId?: string,
  previousKeyId?: string
): WebhookKeyRotationSummary {
  return {
    skipped: Boolean(reason),
    ...(reason ? { reason } : {}),
    scanned: 0,
    rotated: 0,
    conflicts: 0,
    failed: 0,
    remaining: 0,
    blocked: 0,
    ...(currentKeyId ? { currentKeyId } : {}),
    ...(previousKeyId ? { previousKeyId } : {})
  };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

async function rotationCounts(
  env: WebhookKeyRotationEnv,
  currentKeyId: string,
  previousKeyId: string
): Promise<{ remaining: number; blocked: number }> {
  const row = await env.DB.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN encryption_key_id <> ? THEN 1 ELSE 0 END), 0) AS remaining,
      COALESCE(SUM(CASE WHEN encryption_key_id NOT IN (?, ?) THEN 1 ELSE 0 END), 0) AS blocked
    FROM webhook_endpoints
    WHERE deleted_at IS NULL
  `).bind(currentKeyId, currentKeyId, previousKeyId)
    .first<{ remaining: number; blocked: number }>();
  return {
    remaining: Number(row?.remaining ?? 0),
    blocked: Number(row?.blocked ?? 0)
  };
}

/**
 * Re-encrypt a bounded batch of active endpoints from the configured previous
 * key to the current key. Ciphertext is never returned or logged. Each update
 * is compare-and-swap guarded by the old ciphertext/nonces and key id so a
 * concurrent endpoint edit or another rotation worker cannot overwrite it.
 *
 * Keep the previous secret configured until remaining === 0. Rows using an
 * unknown key id are counted as blocked and are deliberately left untouched.
 */
export async function rotateWebhookEncryptionBatch(
  env: WebhookKeyRotationEnv,
  options: { limit?: number; now?: Date } = {}
): Promise<WebhookKeyRotationSummary> {
  let keyring;
  try {
    keyring = readWebhookKeyring(env);
  } catch (error) {
    const code = error instanceof Error ? error.message : "";
    const allowed = new Set<WebhookKeyRotationSummary["reason"]>([
      "WEBHOOK_ENCRYPTION_KEY_MISSING",
      "WEBHOOK_ENCRYPTION_KEY_INVALID",
      "WEBHOOK_ENCRYPTION_KEY_ID_INVALID",
      "WEBHOOK_ENCRYPTION_KEY_PREVIOUS_INVALID",
      "WEBHOOK_ENCRYPTION_KEY_PREVIOUS_ID_INVALID",
      "WEBHOOK_ENCRYPTION_KEY_IDS_MUST_DIFFER",
      "WEBHOOK_PREVIOUS_KEY_ID_WITHOUT_KEY"
    ]);
    const reason = allowed.has(code as WebhookKeyRotationSummary["reason"])
      ? code as WebhookKeyRotationSummary["reason"]
      : "WEBHOOK_ENCRYPTION_KEY_INVALID";
    return emptySummary(reason);
  }

  if (!keyring.previous) {
    return emptySummary("PREVIOUS_KEY_NOT_CONFIGURED", keyring.current.id);
  }

  const limit = options.limit ?? DEFAULT_BATCH_LIMIT;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BATCH_LIMIT) {
    throw new Error("WEBHOOK_KEY_ROTATION_LIMIT_INVALID");
  }
  const now = options.now ?? new Date();
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) {
    throw new Error("WEBHOOK_KEY_ROTATION_TIME_INVALID");
  }
  const updatedAt = now.toISOString();

  const selected = await env.DB.prepare(`
    SELECT
      id,
      organization_id AS organizationId,
      destination_hash AS destinationHash,
      destination_ciphertext AS destinationCiphertext,
      destination_nonce AS destinationNonce,
      secret_ciphertext AS secretCiphertext,
      secret_nonce AS secretNonce,
      secret_last4 AS secretLast4,
      encryption_key_version AS encryptionKeyVersion,
      encryption_key_id AS encryptionKeyId
    FROM webhook_endpoints
    WHERE deleted_at IS NULL AND encryption_key_id = ?
    ORDER BY created_at ASC, id ASC
    LIMIT ?
  `).bind(keyring.previous.id, limit).all<EndpointRow>();

  const summary = emptySummary(undefined, keyring.current.id, keyring.previous.id);
  summary.scanned = selected.results.length;
  const statements: D1PreparedStatement[] = [];

  for (const row of selected.results) {
    try {
      if (row.encryptionKeyVersion !== 1 || row.encryptionKeyId !== keyring.previous.id) {
        throw new Error("WEBHOOK_ENCRYPTION_FORMAT_UNSUPPORTED");
      }
      const oldUrlContext = webhookEncryptionContext(
        row.encryptionKeyVersion, row.encryptionKeyId, row.organizationId, row.id, "url"
      );
      const oldSecretContext = webhookEncryptionContext(
        row.encryptionKeyVersion, row.encryptionKeyId, row.organizationId, row.id, "secret"
      );
      const [destination, secret] = await Promise.all([
        decryptWebhookValue({
          ciphertext: row.destinationCiphertext,
          nonce: row.destinationNonce
        }, keyring.previous.value, oldUrlContext),
        decryptWebhookValue({
          ciphertext: row.secretCiphertext,
          nonce: row.secretNonce
        }, keyring.previous.value, oldSecretContext)
      ]);

      const normalized = normalizeWebhookDestination(destination);
      if (normalized.url !== destination ||
          await sha256Hex(destination) !== row.destinationHash ||
          !SECRET_PATTERN.test(secret) ||
          secret.slice(-4) !== row.secretLast4) {
        throw new Error("WEBHOOK_ENDPOINT_AUTHENTICATION_FAILED");
      }

      const newUrlContext = webhookEncryptionContext(
        row.encryptionKeyVersion, keyring.current.id, row.organizationId, row.id, "url"
      );
      const newSecretContext = webhookEncryptionContext(
        row.encryptionKeyVersion, keyring.current.id, row.organizationId, row.id, "secret"
      );
      const [encryptedUrl, encryptedSecret] = await Promise.all([
        encryptWebhookValue(destination, keyring.current.value, newUrlContext),
        encryptWebhookValue(secret, keyring.current.value, newSecretContext)
      ]);

      statements.push(env.DB.prepare(`
        UPDATE webhook_endpoints
        SET destination_ciphertext = ?,
            destination_nonce = ?,
            secret_ciphertext = ?,
            secret_nonce = ?,
            encryption_key_id = ?,
            updated_at = ?
        WHERE id = ? AND organization_id = ? AND deleted_at IS NULL
          AND encryption_key_version = ? AND encryption_key_id = ?
          AND destination_ciphertext = ? AND destination_nonce = ?
          AND secret_ciphertext = ? AND secret_nonce = ?
      `).bind(
        encryptedUrl.ciphertext,
        encryptedUrl.nonce,
        encryptedSecret.ciphertext,
        encryptedSecret.nonce,
        keyring.current.id,
        updatedAt,
        row.id,
        row.organizationId,
        row.encryptionKeyVersion,
        row.encryptionKeyId,
        row.destinationCiphertext,
        row.destinationNonce,
        row.secretCiphertext,
        row.secretNonce
      ));
    } catch {
      // Do not mutate a row whose old key, authenticated data, destination
      // hash, or one-time secret suffix cannot be verified.
      summary.failed += 1;
    }
  }

  if (statements.length) {
    const results = await env.DB.batch(statements);
    for (const result of results) {
      if ((result.meta?.changes ?? 0) === 1) summary.rotated += 1;
      else summary.conflicts += 1;
    }
  }

  const counts = await rotationCounts(env, keyring.current.id, keyring.previous.id);
  summary.remaining = counts.remaining;
  summary.blocked = counts.blocked;
  return summary;
}
