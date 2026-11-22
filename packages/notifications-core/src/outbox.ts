export const DEFAULT_NOTIFICATION_CLAIM_LIMIT = 5;
export const MAX_NOTIFICATION_CLAIM_LIMIT = 10;
export const DEFAULT_NOTIFICATION_LEASE_MS = 90_000;
export const MIN_NOTIFICATION_LEASE_MS = 30_000;
export const MAX_NOTIFICATION_LEASE_MS = 300_000;
export const MAX_NOTIFICATION_ATTEMPTS = 6;

const RETRY_DELAYS_SECONDS = [30, 120, 600, 3_600, 21_600] as const;

export interface NotificationDelivery {
  id: string;
  organizationId: string;
  incidentId: string | null;
  channelId: string | null;
  eventId: string | null;
  eventType: string | null;
  recipientEmail: string | null;
  attemptCount: number;
  leaseToken: string;
  leaseUntil: string;
}

export interface NotificationClaimOptions {
  now?: Date | string;
  leaseMs?: number;
  limit?: number;
  token?: string;
}

function parseTimestamp(value: Date | string, label: string): { milliseconds: number; iso: string } {
  if (typeof value === "string" && !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error("NOTIFICATION_" + label + "_INVALID");
  }
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  const milliseconds = date.getTime();
  if (!Number.isFinite(milliseconds)) throw new Error("NOTIFICATION_" + label + "_INVALID");
  return { milliseconds, iso: date.toISOString() };
}

/** Claim a bounded batch of due email deliveries with an expiring lease. */
export async function claimDueNotificationDeliveries(
  db: D1Database,
  options: NotificationClaimOptions = {}
): Promise<NotificationDelivery[]> {
  const now = parseTimestamp(options.now ?? new Date(), "NOW");
  const leaseMs = options.leaseMs ?? DEFAULT_NOTIFICATION_LEASE_MS;
  const limit = options.limit ?? DEFAULT_NOTIFICATION_CLAIM_LIMIT;
  const token = options.token ?? crypto.randomUUID();

  if (!Number.isInteger(leaseMs) || leaseMs < MIN_NOTIFICATION_LEASE_MS || leaseMs > MAX_NOTIFICATION_LEASE_MS) {
    throw new Error("NOTIFICATION_LEASE_INVALID");
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_NOTIFICATION_CLAIM_LIMIT) {
    throw new Error("NOTIFICATION_LIMIT_INVALID");
  }
  if (typeof token !== "string" || token.length < 16 || token.length > 128 || /\s/.test(token)) {
    throw new Error("NOTIFICATION_TOKEN_INVALID");
  }

  const leaseUntil = new Date(now.milliseconds + leaseMs).toISOString();
  const claimSql = `
    UPDATE notification_deliveries
    SET lease_token = ?, lease_until = ?, attempt_count = attempt_count + 1, updated_at = ?
    WHERE id IN (
      SELECT id
      FROM notification_deliveries
      WHERE status = 'queued'
        AND next_attempt_at IS NOT NULL
        AND next_attempt_at <= ?
        AND (lease_until IS NULL OR lease_until <= ?)
        AND attempt_count < ?
      ORDER BY next_attempt_at ASC, id ASC
      LIMIT ?
    )
      AND status = 'queued'
      AND next_attempt_at IS NOT NULL
      AND next_attempt_at <= ?
      AND (lease_until IS NULL OR lease_until <= ?)
      AND attempt_count < ?`;

  const selectSql = `
    SELECT id,
      organization_id AS organizationId,
      incident_id AS incidentId,
      channel_id AS channelId,
      event_id AS eventId,
      event_type AS eventType,
      recipient_email AS recipientEmail,
      attempt_count AS attemptCount,
      lease_token AS leaseToken,
      lease_until AS leaseUntil
    FROM notification_deliveries
    WHERE lease_token = ? AND lease_until = ? AND status = 'queued'
    ORDER BY next_attempt_at ASC, id ASC`;

  const results = await db.batch([
    db.prepare(claimSql).bind(
      token, leaseUntil, now.iso, now.iso, now.iso,
      MAX_NOTIFICATION_ATTEMPTS, limit, now.iso, now.iso, MAX_NOTIFICATION_ATTEMPTS
    ),
    db.prepare(selectSql).bind(token, leaseUntil)
  ]);

  return (results[1]?.results ?? []) as unknown as NotificationDelivery[];
}

/** Return a bounded retry delay. The provider Retry-After hint is never ignored. */
export function notificationRetryDelaySeconds(attemptCount: number, retryAfterSeconds?: number | null): number | null {
  if (!Number.isInteger(attemptCount) || attemptCount < 1) throw new Error("NOTIFICATION_ATTEMPT_INVALID");
  const base = RETRY_DELAYS_SECONDS[attemptCount - 1];
  if (base === undefined) return null;
  const providerHint = retryAfterSeconds === undefined || retryAfterSeconds === null
    ? 0
    : Number.isFinite(retryAfterSeconds) && retryAfterSeconds > 0
      ? Math.ceil(retryAfterSeconds)
      : 0;
  return Math.min(21_600, Math.max(base, providerHint));
}

/** Parse either delta-seconds or an HTTP date, returning a bounded positive delay. */
export function parseRetryAfter(value: string | null, now = Date.now()): number | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return Math.min(21_600, Math.max(1, Number(trimmed)));
  if (!/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(trimmed)) return null;
  const timestamp = Date.parse(trimmed);
  if (!Number.isFinite(timestamp)) return null;
  return Math.min(21_600, Math.max(1, Math.ceil((timestamp - now) / 1000)));
}

export type NotificationSettlement =
  | { kind: "sent"; providerMessageId: string; now?: Date | string }
  | { kind: "retry"; errorCode: string; retryAfterSeconds?: number | null; now?: Date | string }
  | { kind: "failed"; errorCode: string; now?: Date | string };

/** Settle only while the caller still owns the delivery lease. */
export async function settleNotificationDelivery(
  db: D1Database,
  delivery: Pick<NotificationDelivery, "id" | "leaseToken" | "attemptCount">,
  settlement: NotificationSettlement
): Promise<boolean> {
  if (!delivery.id || !delivery.leaseToken || delivery.leaseToken.length > 128 ||
      !Number.isInteger(delivery.attemptCount) || delivery.attemptCount < 1) {
    throw new Error("NOTIFICATION_CLAIM_INVALID");
  }
  const now = parseTimestamp(settlement.now ?? new Date(), "NOW");
  let statement: D1PreparedStatement;

  if (settlement.kind === "sent") {
    const providerMessageId = settlement.providerMessageId.trim().slice(0, 128);
    if (!providerMessageId) throw new Error("NOTIFICATION_PROVIDER_ID_INVALID");
    statement = db.prepare(`
      UPDATE notification_deliveries
      SET status = 'sent', provider_message_id = ?, delivered_at = ?,
          next_attempt_at = NULL, last_error_code = NULL,
          lease_token = NULL, lease_until = NULL, updated_at = ?
      WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`)
      .bind(providerMessageId, now.iso, now.iso, delivery.id, delivery.leaseToken, now.iso);
  } else if (settlement.kind === "failed") {
    const errorCode = settlement.errorCode.trim();
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(errorCode)) throw new Error("NOTIFICATION_ERROR_CODE_INVALID");
    statement = db.prepare(`
      UPDATE notification_deliveries
      SET status = 'failed', next_attempt_at = NULL, last_error_code = ?,
          lease_token = NULL, lease_until = NULL, updated_at = ?
      WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`)
      .bind(errorCode, now.iso, delivery.id, delivery.leaseToken, now.iso);
  } else {
    const errorCode = settlement.errorCode.trim();
    if (!/^[A-Z][A-Z0-9_]{0,63}$/.test(errorCode)) throw new Error("NOTIFICATION_ERROR_CODE_INVALID");
    const delay = notificationRetryDelaySeconds(delivery.attemptCount, settlement.retryAfterSeconds);
    if (delay === null) {
      statement = db.prepare(`
        UPDATE notification_deliveries
        SET status = 'failed', next_attempt_at = NULL, last_error_code = ?,
            lease_token = NULL, lease_until = NULL, updated_at = ?
        WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`)
        .bind("RETRY_EXHAUSTED_" + errorCode, now.iso, delivery.id, delivery.leaseToken, now.iso);
    } else {
      const nextAttemptAt = new Date(now.milliseconds + delay * 1000).toISOString();
      statement = db.prepare(`
        UPDATE notification_deliveries
        SET status = 'queued', next_attempt_at = ?, last_error_code = ?,
            lease_token = NULL, lease_until = NULL, updated_at = ?
        WHERE id = ? AND lease_token = ? AND status = 'queued' AND lease_until > ?`)
        .bind(nextAttemptAt, errorCode, now.iso, delivery.id, delivery.leaseToken, now.iso);
    }
  }

  const result = await statement.run();
  return (result.meta?.changes ?? 0) === 1;
}
