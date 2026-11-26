import { validateProbeAgentEndpoint } from "../../probe-client/src/client.mjs";
import { sendWebhookJob, type WebhookJob, type WebhookResult } from "../../probe-client/src/webhook-client.mjs";
import { claimDueWebhookDeliveries, settleWebhookDelivery, type WebhookDelivery } from "./webhook-outbox";
import { decryptWebhookValue, WEBHOOK_ENCRYPTION_KEY_VERSION } from "./webhook-secrets";
import { signWebhookPayload } from "./webhook-signing";

export interface WebhookDispatchEnv {
  DB: D1Database;
  WEBHOOKS_ENABLED?: string;
  WEBHOOK_ENCRYPTION_KEY?: string;
  PROBE_AGENT_URL?: string;
  PROBE_SHARED_SECRET?: string;
}

export interface WebhookDispatchSummary {
  skipped: boolean;
  reason?: "WEBHOOKS_DISABLED" | "WEBHOOK_ENCRYPTION_KEY_MISSING" |
    "WEBHOOK_ENCRYPTION_KEY_INVALID" | "WEBHOOK_AGENT_CONFIGURATION_MISSING" |
    "WEBHOOK_AGENT_CONFIGURATION_INVALID";
  claimed: number;
  sent: number;
  retried: number;
  failed: number;
  stale: number;
  dispatchErrors: number;
}

export interface WebhookDispatchOptions {
  now?: Date | string;
  clock?: () => Date;
  limit?: number;
  concurrency?: number;
  sender?: typeof sendWebhookJob;
}

interface WebhookDeliveryContext {
  destinationCiphertext: string;
  destinationNonce: string;
  secretCiphertext: string;
  secretNonce: string;
  encryptionKeyVersion: number;
  organizationName: string;
  monitorName: string;
  incidentStatus: string;
  incidentSummary: string | null;
  eventType: string;
  eventVisibility: string;
  eventMessage: string | null;
  eventCreatedAt: string;
}

const DEFAULT_BATCH_LIMIT = 3;
const MAX_BATCH_LIMIT = 5;
const DEFAULT_CONCURRENCY = 2;
const MAX_CONCURRENCY = 3;
const LEASE_MS = 90_000;
const MAX_PAYLOAD_BYTES = 256 * 1024;
const ALLOWED_EVENT_TYPES = new Set([
  "incident.opened",
  "incident.monitoring",
  "incident.resolved",
  "incident.reopened",
  "incident.status_changed",
  "incident.update"
]);
const RETRYABLE_ERRORS = new Set([
  "TIMEOUT",
  "DNS_FAILURE",
  "NETWORK_ERROR",
  "TLS_ERROR",
  "REMOTE_RATE_LIMITED",
  "REMOTE_SERVER_ERROR",
  "REMOTE_RESPONSE_INVALID",
  "WEBHOOK_AGENT_UNAVAILABLE",
  "WEBHOOK_AGENT_AUTH_FAILED",
  "WEBHOOK_AGENT_INVALID_RESPONSE",
  "WEBHOOK_AGENT_RESPONSE_TOO_LARGE"
]);

function toDate(value: Date | string): Date {
  if (typeof value === "string" &&
      !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error("WEBHOOK_NOW_INVALID");
  }
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  if (!Number.isFinite(date.getTime())) throw new Error("WEBHOOK_NOW_INVALID");
  return date;
}

function safeText(value: string | null, maxLength: number): string {
  return (value ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLength);
}

function isoTimestamp(value: string): string {
  const raw = value.trim();
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(raw)
    ? raw.replace(" ", "T") + "Z"
    : raw;
  const milliseconds = Date.parse(normalized);
  if (!Number.isFinite(milliseconds)) throw new Error("WEBHOOK_EVENT_TIMESTAMP_INVALID");
  return new Date(milliseconds).toISOString();
}

export function webhookDispatchDisabledReason(
  env: Pick<WebhookDispatchEnv, "WEBHOOKS_ENABLED" | "WEBHOOK_ENCRYPTION_KEY" | "PROBE_AGENT_URL" | "PROBE_SHARED_SECRET">
): WebhookDispatchSummary["reason"] | undefined {
  if (env.WEBHOOKS_ENABLED !== "true") return "WEBHOOKS_DISABLED";
  if (!env.WEBHOOK_ENCRYPTION_KEY) return "WEBHOOK_ENCRYPTION_KEY_MISSING";
  if (!/^[A-Za-z0-9_-]{43}$/.test(env.WEBHOOK_ENCRYPTION_KEY)) return "WEBHOOK_ENCRYPTION_KEY_INVALID";
  if (!env.PROBE_AGENT_URL || !env.PROBE_SHARED_SECRET ||
      new TextEncoder().encode(env.PROBE_SHARED_SECRET).byteLength < 32) {
    return "WEBHOOK_AGENT_CONFIGURATION_MISSING";
  }
  try {
    validateProbeAgentEndpoint(env.PROBE_AGENT_URL);
  } catch {
    return "WEBHOOK_AGENT_CONFIGURATION_INVALID";
  }
  return undefined;
}

export function isWebhookDeliveryConfigured(env: WebhookDispatchEnv): boolean {
  return webhookDispatchDisabledReason(env) === undefined;
}

async function loadDeliveryContext(
  db: D1Database,
  delivery: WebhookDelivery,
  now: string
): Promise<WebhookDeliveryContext | null> {
  return db.prepare(`
    SELECT
      e.destination_ciphertext AS destinationCiphertext,
      e.destination_nonce AS destinationNonce,
      e.secret_ciphertext AS secretCiphertext,
      e.secret_nonce AS secretNonce,
      e.encryption_key_version AS encryptionKeyVersion,
      o.name AS organizationName,
      m.name AS monitorName,
      i.status AS incidentStatus,
      i.summary AS incidentSummary,
      ev.event_type AS eventType,
      ev.visibility AS eventVisibility,
      ev.message AS eventMessage,
      ev.created_at AS eventCreatedAt
    FROM webhook_deliveries d
    JOIN webhook_endpoints e
      ON e.id = d.endpoint_id AND e.organization_id = d.organization_id
      AND e.is_enabled = 1 AND e.deleted_at IS NULL
    JOIN incident_events ev
      ON ev.id = d.event_id AND ev.incident_id = d.incident_id
    JOIN incidents i ON i.id = d.incident_id
    JOIN monitors m
      ON m.id = i.monitor_id AND m.organization_id = d.organization_id
    JOIN organizations o ON o.id = d.organization_id
    WHERE d.id = ? AND d.organization_id = ? AND d.endpoint_id = ?
      AND d.event_id = ? AND d.lease_token = ?
      AND d.status = 'queued' AND d.lease_until > ?
      AND (
        ev.event_type NOT IN ('incident.update', 'incident.status_changed')
        OR ev.visibility = 'public'
      )
  `).bind(
    delivery.id,
    delivery.organizationId,
    delivery.endpointId,
    delivery.eventId,
    delivery.leaseToken,
    now
  ).first<WebhookDeliveryContext>();
}

async function isDeliveryCurrent(
  db: D1Database,
  delivery: WebhookDelivery,
  context: WebhookDeliveryContext,
  now: string
): Promise<boolean> {
  const row = await db.prepare(`
    SELECT 1 AS eligible
    FROM webhook_deliveries d
    JOIN webhook_endpoints e
      ON e.id = d.endpoint_id AND e.organization_id = d.organization_id
    WHERE d.id = ? AND d.organization_id = ? AND d.endpoint_id = ?
      AND d.event_id = ? AND d.lease_token = ?
      AND d.status = 'queued' AND d.lease_until > ?
      AND e.is_enabled = 1 AND e.deleted_at IS NULL
      AND e.destination_ciphertext = ? AND e.destination_nonce = ?
      AND e.secret_ciphertext = ? AND e.secret_nonce = ?
      AND e.encryption_key_version = ?
  `).bind(
    delivery.id,
    delivery.organizationId,
    delivery.endpointId,
    delivery.eventId,
    delivery.leaseToken,
    now,
    context.destinationCiphertext,
    context.destinationNonce,
    context.secretCiphertext,
    context.secretNonce,
    context.encryptionKeyVersion
  ).first<{ eligible: number }>();
  return row?.eligible === 1;
}

async function hasLiveLease(
  db: D1Database,
  delivery: WebhookDelivery,
  now: string
): Promise<boolean> {
  const row = await db.prepare(`
    SELECT 1 AS eligible
    FROM webhook_deliveries d
    JOIN webhook_endpoints e
      ON e.id = d.endpoint_id AND e.organization_id = d.organization_id
    WHERE d.id = ? AND d.lease_token = ? AND d.status = 'queued'
      AND d.lease_until > ? AND e.is_enabled = 1 AND e.deleted_at IS NULL
  `).bind(delivery.id, delivery.leaseToken, now).first<{ eligible: number }>();
  return row?.eligible === 1;
}

function buildWebhookPayload(
  delivery: WebhookDelivery,
  context: WebhookDeliveryContext
): string {
  if (!ALLOWED_EVENT_TYPES.has(context.eventType)) throw new Error("WEBHOOK_EVENT_TYPE_UNSUPPORTED");
  const isPublic = context.eventVisibility === "public";
  const incident: Record<string, unknown> = {
    id: delivery.incidentId,
    status: safeText(context.incidentStatus, 40)
  };
  if (isPublic && context.incidentSummary) incident.summary = safeText(context.incidentSummary, 500);
  const data: Record<string, unknown> = {
    workspace: { name: safeText(context.organizationName, 80) },
    monitor: { name: safeText(context.monitorName, 80) },
    incident
  };
  if (isPublic && context.eventMessage) data.message = safeText(context.eventMessage, 1_000);
  const payload = JSON.stringify({
    eventId: delivery.eventId,
    type: context.eventType,
    createdAt: isoTimestamp(context.eventCreatedAt),
    data
  });
  if (new TextEncoder().encode(payload).byteLength > MAX_PAYLOAD_BYTES) {
    throw new Error("WEBHOOK_PAYLOAD_TOO_LARGE");
  }
  return payload;
}

function emptySummary(reason?: WebhookDispatchSummary["reason"]): WebhookDispatchSummary {
  return {
    skipped: Boolean(reason),
    ...(reason ? { reason } : {}),
    claimed: 0,
    sent: 0,
    retried: 0,
    failed: 0,
    stale: 0,
    dispatchErrors: 0
  };
}

/**
 * Drain a small, leased batch of webhook events through the dedicated
 * DNS-pinned agent. The endpoint and encrypted values are rechecked after
 * decryption and immediately before the agent request. Delivery is at-least-
 * once; receivers must deduplicate the stable eventId.
 */
export async function dispatchWebhookBatch(
  env: WebhookDispatchEnv,
  options: WebhookDispatchOptions = {}
): Promise<WebhookDispatchSummary> {
  const disabledReason = webhookDispatchDisabledReason(env);
  if (disabledReason) return emptySummary(disabledReason);

  const limit = options.limit ?? DEFAULT_BATCH_LIMIT;
  const concurrency = options.concurrency ?? DEFAULT_CONCURRENCY;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_BATCH_LIMIT) {
    throw new Error("WEBHOOK_DISPATCH_LIMIT_INVALID");
  }
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > MAX_CONCURRENCY) {
    throw new Error("WEBHOOK_DISPATCH_CONCURRENCY_INVALID");
  }

  const fixedNow = options.now === undefined ? null : toDate(options.now);
  const clock = options.clock ?? (() => fixedNow ? new Date(fixedNow.getTime()) : new Date());
  const now = toDate(clock());
  const deliveries = await claimDueWebhookDeliveries(env.DB, {
    now,
    leaseMs: LEASE_MS,
    limit
  });
  const summary = { ...emptySummary(), claimed: deliveries.length };
  if (!deliveries.length) return summary;

  const sender = options.sender ?? sendWebhookJob;
  const encryptionKey = env.WEBHOOK_ENCRYPTION_KEY as string;
  const agentUrl = env.PROBE_AGENT_URL as string;
  const agentSecret = env.PROBE_SHARED_SECRET as string;

  async function settle(
    delivery: WebhookDelivery,
    outcome: Parameters<typeof settleWebhookDelivery>[2],
    counter: "sent" | "retried" | "failed"
  ): Promise<void> {
    try {
      if (await settleWebhookDelivery(env.DB, delivery, { ...outcome, now: toDate(clock()) })) {
        summary[counter] += 1;
      } else {
        summary.stale += 1;
      }
    } catch {
      summary.dispatchErrors += 1;
    }
  }

  async function processOne(delivery: WebhookDelivery): Promise<void> {
    let context: WebhookDeliveryContext | null;
    try {
      context = await loadDeliveryContext(env.DB, delivery, toDate(clock()).toISOString());
    } catch {
      summary.dispatchErrors += 1;
      return;
    }
    if (!context) {
      await settle(delivery, { kind: "failed", errorCode: "DELIVERY_CONTEXT_UNAVAILABLE" }, "failed");
      return;
    }
    if (context.encryptionKeyVersion !== WEBHOOK_ENCRYPTION_KEY_VERSION) {
      await settle(delivery, { kind: "failed", errorCode: "ENCRYPTION_KEY_VERSION_UNSUPPORTED" }, "failed");
      return;
    }

    let destinationUrl: string;
    let signingSecret: string;
    let payload: string;
    try {
      const [destination, secret] = await Promise.all([
        decryptWebhookValue(
          { ciphertext: context.destinationCiphertext, nonce: context.destinationNonce },
          encryptionKey,
          `zetuwatch:webhook:v${context.encryptionKeyVersion}:${delivery.organizationId}:${delivery.endpointId}:url`
        ),
        decryptWebhookValue(
          { ciphertext: context.secretCiphertext, nonce: context.secretNonce },
          encryptionKey,
          `zetuwatch:webhook:v${context.encryptionKeyVersion}:${delivery.organizationId}:${delivery.endpointId}:secret`
        )
      ]);
      destinationUrl = destination;
      signingSecret = secret;
      payload = buildWebhookPayload(delivery, context);
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      const code = message === "WEBHOOK_EVENT_TYPE_UNSUPPORTED" ||
        message === "WEBHOOK_EVENT_TIMESTAMP_INVALID" ||
        message === "WEBHOOK_PAYLOAD_TOO_LARGE"
        ? message
        : "WEBHOOK_DECRYPT_FAILED";
      await settle(delivery, { kind: "failed", errorCode: code }, "failed");
      return;
    }

    const timestampSeconds = Math.floor(toDate(clock()).getTime() / 1000);
    let signatureHeader: string;
    try {
      signatureHeader = await signWebhookPayload(signingSecret, payload, timestampSeconds);
    } catch {
      await settle(delivery, { kind: "failed", errorCode: "WEBHOOK_SIGNING_FAILED" }, "failed");
      return;
    }

    const preflightAt = toDate(clock()).toISOString();
    let current = false;
    try {
      current = await isDeliveryCurrent(env.DB, delivery, context, preflightAt);
    } catch {
      summary.dispatchErrors += 1;
      return;
    }
    if (!current) {
      try {
        if (await hasLiveLease(env.DB, delivery, preflightAt)) {
          await settle(delivery, {
            kind: "retry",
            errorCode: "ENDPOINT_CONFIGURATION_CHANGED"
          }, "retried");
        } else {
          summary.stale += 1;
        }
      } catch {
        summary.dispatchErrors += 1;
      }
      return;
    }

    const job: WebhookJob = {
      destinationUrl,
      eventId: delivery.eventId,
      payload,
      signatureHeader
    };
    let result: WebhookResult;
    try {
      result = await sender(agentUrl, agentSecret, job, {
        now: () => toDate(clock()).getTime(),
        requestTimeoutMs: 20_000
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "";
      const code = /^WEBHOOK_AGENT_[A-Z0-9_]{1,48}$/.test(message)
        ? message
        : "WEBHOOK_AGENT_UNAVAILABLE";
      await settle(delivery, { kind: "retry", errorCode: code }, "retried");
      return;
    }

    if (result.delivered && result.responseStatus !== null) {
      await settle(delivery, { kind: "sent", responseStatus: result.responseStatus }, "sent");
    } else {
      const code = result.errorCode && /^[A-Z][A-Z0-9_]{0,63}$/.test(result.errorCode)
        ? result.errorCode
        : "WEBHOOK_RESULT_INVALID";
      if (RETRYABLE_ERRORS.has(code)) {
        await settle(delivery, {
          kind: "retry",
          errorCode: code,
          responseStatus: result.responseStatus,
          retryAfterSeconds: result.retryAfterSeconds
        }, "retried");
      } else {
        await settle(delivery, {
          kind: "failed",
          errorCode: code,
          responseStatus: result.responseStatus
        }, "failed");
      }
    }
  }

  let cursor = 0;
  const worker = async (): Promise<void> => {
    while (cursor < deliveries.length) {
      const index = cursor++;
      await processOne(deliveries[index]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, deliveries.length) }, () => worker()));
  return summary;
}
