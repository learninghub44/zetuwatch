export const DEFAULT_WEBHOOK_CLAIM_LIMIT = 5;
export const MAX_WEBHOOK_CLAIM_LIMIT = 10;
export const DEFAULT_WEBHOOK_LEASE_MS = 90_000;
export const MIN_WEBHOOK_LEASE_MS = 30_000;
export const MAX_WEBHOOK_LEASE_MS = 300_000;
export const MAX_WEBHOOK_ATTEMPTS = 8;

const RETRY_DELAYS_SECONDS = [30, 120, 600, 1_800, 7_200, 21_600, 21_600] as const;

export interface WebhookDelivery {
  id: string;
  organizationId: string;
  endpointId: string;
  incidentId: string;
  eventId: string;
  attemptCount: number;
  leaseToken: string;
  leaseUntil: string;
}

export interface WebhookClaimOptions {
  now?: Date | string;
  leaseMs?: number;
  limit?: number;
  token?: string;
}

function parseTimestamp(value: Date | string, label: string): { milliseconds: number; iso: string } {
  if (typeof value === "string" &&
      !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error("WEBHOOK_" + label + "_INVALID");
  }
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  const milliseconds = date.getTime();
  if (!Number.isFinite(milliseconds)) throw new Error("WEBHOOK_" + label + "_INVALID");
  return { milliseconds, iso: date.toISOString() };
}

function validErrorCode(value: string): boolean {
  return /^[A-Z][A-Z0-9_]{0,63}$/.test(value);
}

function validResponseStatus(value: number | null | undefined): value is number | null | undefined {
  return value === null || value === undefined ||
    (Number.isInteger(value) && value >= 100 && value <= 599);
}

/** Bounded exponential retry policy; the final attempt is terminal. */
export function webhookRetryDelaySeconds(
  attemptCount: number,
  retryAfterSeconds?: number | null
): number | null {
  if (!Number.isInteger(attemptCount) || attemptCount < 1 || attemptCount > MAX_WEBHOOK_ATTEMPTS) {
    throw new Error("WEBHOOK_ATTEMPT_INVALID");
  }
  const base = RETRY_DELAYS_SECONDS[attemptCount - 1];
  if (base === undefined) return null;
  const providerHint = retryAfterSeconds === undefined || retryAfterSeconds === null
    ? 0
    : Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
      ? Math.ceil(retryAfterSeconds)
      : 0;
  return Math.min(21_600, Math.max(base, providerHint));
}

/** Claim due deliveries only while their endpoint is enabled and not deleted. */
export async function claimDueWebhookDeliveries(
  db: D1Database,
  options: WebhookClaimOptions = {}
): Promise<WebhookDelivery[]> {
  const now = parseTimestamp(options.now ?? new Date(), "NOW");
  const leaseMs = options.leaseMs ?? DEFAULT_WEBHOOK_LEASE_MS;
  const limit = options.limit ?? DEFAULT_WEBHOOK_CLAIM_LIMIT;
  const token = options.token ?? crypto.randomUUID();

  if (!Number.isInteger(leaseMs) || leaseMs < MIN_WEBHOOK_LEASE_MS || leaseMs > MAX_WEBHOOK_LEASE_MS) {
    throw new Error("WEBHOOK_LEASE_INVALID");
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_WEBHOOK_CLAIM_LIMIT) {
    throw new Error("WEBHOOK_LIMIT_INVALID");
  }
  if (typeof token !== "string" || token.length < 16 || token.length > 128 || /\s/.test(token)) {
    throw new Error("WEBHOOK_TOKEN_INVALID");
  }

  const leaseUntil = new Date(now.milliseconds + leaseMs).toISOString();
  const claimSql = `
    UPDATE webhook_deliveries
    SET lease_token = ?, lease_until = ?, attempt_count = attempt_count + 1, updated_at = ?
    WHERE id IN (
      SELECT d.id
      FROM webhook_deliveries d
      JOIN webhook_endpoints e
        ON e.id = d.endpoint_id
        AND e.organization_id = d.organization_id
        AND e.is_enabled = 1
        AND e.deleted_at IS NULL
      WHERE d.status = 'queued'
        AND d.next_attempt_at <= ?
        AND (d.lease_until IS NULL OR d.lease_until <= ?)
        AND d.attempt_count < ?
      ORDER BY d.next_attempt_at ASC, d.id ASC
      LIMIT ?
    )
      AND status = 'queued'
      AND next_attempt_at <= ?
      AND (lease_until IS NULL OR lease_until <= ?)
      AND attempt_count < ?
      AND EXISTS (
        SELECT 1 FROM webhook_endpoints e
        WHERE e.id = webhook_deliveries.endpoint_id
          AND e.organization_id = webhook_deliveries.organization_id
          AND e.is_enabled = 1 AND e.deleted_at IS NULL
      )`;

  const selectSql = `
    SELECT id,
      organization_id AS organizationId,
      endpoint_id AS endpointId,
      incident_id AS incidentId,
      event_id AS eventId,
      attempt_count AS attemptCount,
      lease_token AS leaseToken,
      lease_until AS leaseUntil
    FROM webhook_deliveries
    WHERE lease_token = ? AND lease_until = ? AND status = 'queued'
    ORDER BY next_attempt_at ASC, id ASC`;

  const results = await db.batch([
    db.prepare(claimSql).bind(
      token, leaseUntil, now.iso, now.iso, now.iso,
      MAX_WEBHOOK_ATTEMPTS, limit, now.iso, now.iso, MAX_WEBHOOK_ATTEMPTS
    ),
    db.prepare(selectSql).bind(token, leaseUntil)
  ]);

  return (results[1]?.results ?? []) as unknown as WebhookDelivery[];
}

export type WebhookSettlement =
  | { kind: "sent"; responseStatus: number; now?: Date | string }
  | { kind: "retry"; errorCode: string; responseStatus?: number | null; retryAfterSeconds?: number | null; now?: Date | string }
  | { kind: "failed"; errorCode: string; responseStatus?: number | null; now?: Date | string };

/**
 * Settle a delivery and its current attempt log atomically. A stale or expired
 * lease cannot change either row; completed attempt records are append-only.
 */
export async function settleWebhookDelivery(
  db: D1Database,
  delivery: Pick<WebhookDelivery, "id" | "leaseToken" | "attemptCount">,
  settlement: WebhookSettlement
): Promise<boolean> {
  if (!delivery.id || typeof delivery.leaseToken !== "string" ||
      delivery.leaseToken.length < 16 || delivery.leaseToken.length > 128 ||
      /\s/.test(delivery.leaseToken) ||
      !Number.isInteger(delivery.attemptCount) ||
      delivery.attemptCount < 1 || delivery.attemptCount > MAX_WEBHOOK_ATTEMPTS) {
    throw new Error("WEBHOOK_CLAIM_INVALID");
  }

  const now = parseTimestamp(settlement.now ?? new Date(), "NOW");
  let deliveryStatus: "sent" | "queued" | "failed";
  let deliverySql: string;
  let deliveryBindings: Array<string | number | null>;
  let attemptStatus: "sent" | "retry" | "failed";
  let responseStatus: number | null = settlement.responseStatus ?? null;
  let errorCode: string | null = null;

  if (!validResponseStatus(responseStatus)) throw new Error("WEBHOOK_RESPONSE_STATUS_INVALID");

  if (settlement.kind === "sent") {
    if (!Number.isInteger(settlement.responseStatus) ||
        settlement.responseStatus < 200 || settlement.responseStatus > 299) {
      throw new Error("WEBHOOK_SUCCESS_STATUS_INVALID");
    }
    deliveryStatus = "sent";
    attemptStatus = "sent";
    deliverySql = `
      UPDATE webhook_deliveries
      SET status = 'sent', response_status = ?, delivered_at = ?,
          next_attempt_at = NULL, last_error_code = NULL,
          lease_token = NULL, lease_until = NULL, updated_at = ?
      WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`;
    deliveryBindings = [
      settlement.responseStatus, now.iso, now.iso,
      delivery.id, delivery.leaseToken, now.iso
    ];
  } else if (settlement.kind === "failed") {
    errorCode = settlement.errorCode.trim();
    if (!validErrorCode(errorCode)) throw new Error("WEBHOOK_ERROR_CODE_INVALID");
    deliveryStatus = "failed";
    attemptStatus = "failed";
    deliverySql = `
      UPDATE webhook_deliveries
      SET status = 'failed', response_status = ?, next_attempt_at = NULL,
          last_error_code = ?, lease_token = NULL, lease_until = NULL, updated_at = ?
      WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`;
    deliveryBindings = [
      responseStatus, errorCode, now.iso,
      delivery.id, delivery.leaseToken, now.iso
    ];
  } else {
    errorCode = settlement.errorCode.trim();
    if (!validErrorCode(errorCode)) throw new Error("WEBHOOK_ERROR_CODE_INVALID");
    const delay = webhookRetryDelaySeconds(delivery.attemptCount, settlement.retryAfterSeconds);
    if (delay === null) {
      errorCode = "RETRY_EXHAUSTED_" + errorCode;
      deliveryStatus = "failed";
      attemptStatus = "failed";
      deliverySql = `
        UPDATE webhook_deliveries
        SET status = 'failed', response_status = ?, next_attempt_at = NULL,
            last_error_code = ?, lease_token = NULL, lease_until = NULL, updated_at = ?
        WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`;
      deliveryBindings = [
        responseStatus, errorCode, now.iso,
        delivery.id, delivery.leaseToken, now.iso
      ];
    } else {
      const nextAttemptAt = new Date(now.milliseconds + delay * 1000).toISOString();
      deliveryStatus = "queued";
      attemptStatus = "retry";
      deliverySql = `
        UPDATE webhook_deliveries
        SET status = 'queued', response_status = ?, next_attempt_at = ?,
            last_error_code = ?, lease_token = NULL, lease_until = NULL, updated_at = ?
        WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`;
      deliveryBindings = [
        responseStatus, nextAttemptAt, errorCode, now.iso,
        delivery.id, delivery.leaseToken, now.iso
      ];
    }
  }

  const attemptSql = `
    UPDATE webhook_delivery_attempts
    SET status = ?, response_status = ?, error_code = ?, completed_at = ?
    WHERE delivery_id = ? AND attempt_number = ? AND status = 'started'
      AND EXISTS (
        SELECT 1 FROM webhook_deliveries d
        WHERE d.id = ? AND d.attempt_count = ? AND d.lease_token IS NULL AND d.status = ?
      )`;

  const results = await db.batch([
    db.prepare(deliverySql).bind(...deliveryBindings),
    db.prepare(attemptSql).bind(
      attemptStatus, responseStatus, errorCode, now.iso,
      delivery.id, delivery.attemptCount,
      delivery.id, delivery.attemptCount, deliveryStatus
    )
  ]);

  return (results[0]?.meta?.changes ?? 0) === 1;
}
