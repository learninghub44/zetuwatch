export const DEFAULT_CLAIM_LIMIT = 10;
export const MAX_CLAIM_LIMIT = 25;
export const DEFAULT_LEASE_MS = 120_000;
export const MIN_LEASE_MS = 30_000;
export const MAX_LEASE_MS = 300_000;

export interface ClaimedMonitor {
  id: string;
  organizationId: string;
  name: string;
  targetUrl: string;
  method: string;
  expectedStatus: number;
  intervalSeconds: number;
  timeoutMs: number;
  nextCheckAt: string;
  leaseToken: string;
  leaseUntil: string;
}

export interface ClaimOptions {
  now?: Date | string;
  leaseMs?: number;
  limit?: number;
  token?: string;
}

export interface FinalizeCheckInput {
  monitorId: string;
  leaseToken: string;
  checkedAt: Date | string;
  nextCheckAt: Date | string;
  isUp: boolean;
  statusCode: number | null;
  responseTimeMs: number;
  errorCode?: string | null;
  checkId?: string;
}

function timestamp(value: Date | string, label: string): { milliseconds: number; sql: string; iso: string } {
  if (typeof value === "string" && !/^\d{4}-\d{2}-\d{2}T.*(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    throw new Error("SCHEDULER_" + label + "_INVALID");
  }
  const date = value instanceof Date ? new Date(value.getTime()) : new Date(value);
  const milliseconds = date.getTime();
  if (!Number.isFinite(milliseconds)) throw new Error("SCHEDULER_" + label + "_INVALID");
  const iso = date.toISOString();
  return { milliseconds, iso, sql: iso.slice(0, 19).replace("T", " ") };
}

function validateClaimOptions(options: ClaimOptions): {
  now: ReturnType<typeof timestamp>;
  leaseMs: number;
  limit: number;
  token: string;
} {
  const now = timestamp(options.now ?? new Date(), "NOW");
  const leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
  const limit = options.limit ?? DEFAULT_CLAIM_LIMIT;
  const token = options.token ?? crypto.randomUUID();

  if (!Number.isInteger(leaseMs) || leaseMs < MIN_LEASE_MS || leaseMs > MAX_LEASE_MS) {
    throw new Error("SCHEDULER_LEASE_INVALID");
  }
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_CLAIM_LIMIT) {
    throw new Error("SCHEDULER_LIMIT_INVALID");
  }
  if (typeof token !== "string" || token.length < 16 || token.length > 128 || /\s/.test(token)) {
    throw new Error("SCHEDULER_TOKEN_INVALID");
  }
  return { now, leaseMs, limit, token };
}

/**
 * Atomically lease a bounded batch of due monitors.
 *
 * D1 batch executes statements sequentially in one transaction. The update
 * selects due rows and installs a unique lease token before the following
 * select reads them, so overlapping scheduler invocations cannot claim the
 * same monitor. The due timestamp is deliberately unchanged until a check is
 * durably finalized; abandoned work becomes eligible again at lease expiry.
 */
export async function claimDueMonitors(
  db: D1Database,
  options: ClaimOptions = {}
): Promise<ClaimedMonitor[]> {
  const { now, leaseMs, limit, token } = validateClaimOptions(options);
  const leaseUntil = new Date(now.milliseconds + leaseMs).toISOString();

  const claimSql = [
    "UPDATE monitors",
    "SET check_lease_token = ?, check_lease_until = ?, last_claimed_at = ?",
    "WHERE id IN (",
    "  SELECT id FROM monitors",
    "  WHERE is_enabled = 1",
    "    AND next_check_at <= ?",
    "    AND (check_lease_until IS NULL OR check_lease_until <= ?)",
    "  ORDER BY next_check_at ASC, id ASC",
    "  LIMIT ?",
    ")",
    "AND is_enabled = 1",
    "AND next_check_at <= ?",
    "AND (check_lease_until IS NULL OR check_lease_until <= ?)"
  ].join("\n");

  const selectSql = [
    "SELECT",
    "  id,",
    "  organization_id AS organizationId,",
    "  name,",
    "  target_url AS targetUrl,",
    "  method,",
    "  expected_status AS expectedStatus,",
    "  interval_seconds AS intervalSeconds,",
    "  timeout_ms AS timeoutMs,",
    "  next_check_at AS nextCheckAt,",
    "  check_lease_token AS leaseToken,",
    "  check_lease_until AS leaseUntil",
    "FROM monitors",
    "WHERE check_lease_token = ? AND check_lease_until = ?",
    "ORDER BY next_check_at ASC, id ASC"
  ].join("\n");

  const results = await db.batch([
    db.prepare(claimSql).bind(token, leaseUntil, now.iso, now.sql, now.iso, limit, now.sql, now.iso),
    db.prepare(selectSql).bind(token, leaseUntil)
  ]);

  return (results[1]?.results ?? []) as unknown as ClaimedMonitor[];
}

/** Release a claim after a transient worker failure without moving its due time. */
export async function releaseMonitorClaim(
  db: D1Database,
  monitorId: string,
  leaseToken: string
): Promise<boolean> {
  if (!monitorId || !leaseToken || leaseToken.length > 128) throw new Error("SCHEDULER_CLAIM_INVALID");
  const result = await db.prepare(
    "UPDATE monitors SET check_lease_token = NULL, check_lease_until = NULL WHERE id = ? AND check_lease_token = ?"
  ).bind(monitorId, leaseToken).run();
  return (result.meta?.changes ?? 0) === 1;
}

/**
 * Persist one result and advance its schedule only while the caller still owns
 * the lease. The conditional insert prevents stale workers from appending a
 * check after a lease has been reclaimed by another invocation.
 */
export async function finalizeMonitorCheck(
  db: D1Database,
  input: FinalizeCheckInput
): Promise<boolean> {
  if (!input.monitorId || typeof input.leaseToken !== "string" ||
      input.leaseToken.length < 16 || input.leaseToken.length > 128) {
    throw new Error("SCHEDULER_CLAIM_INVALID");
  }
  if (typeof input.isUp !== "boolean") throw new Error("SCHEDULER_RESULT_INVALID");
  if (input.statusCode !== null &&
      (!Number.isInteger(input.statusCode) || input.statusCode < 100 || input.statusCode > 599)) {
    throw new Error("SCHEDULER_STATUS_INVALID");
  }
  if (!Number.isInteger(input.responseTimeMs) || input.responseTimeMs < 0 || input.responseTimeMs > 30_000) {
    throw new Error("SCHEDULER_RESPONSE_TIME_INVALID");
  }
  const errorCode = input.errorCode ?? null;
  if (errorCode !== null && (typeof errorCode !== "string" || !/^[A-Z][A-Z0-9_]{0,63}$/.test(errorCode))) {
    throw new Error("SCHEDULER_ERROR_CODE_INVALID");
  }

  const checkedAt = timestamp(input.checkedAt, "CHECKED_AT");
  const nextCheckAt = timestamp(input.nextCheckAt, "NEXT_CHECK_AT");
  if (nextCheckAt.milliseconds <= checkedAt.milliseconds) {
    throw new Error("SCHEDULER_NEXT_CHECK_INVALID");
  }
  const checkId = input.checkId ?? crypto.randomUUID();
  if (!checkId || checkId.length > 128) throw new Error("SCHEDULER_CHECK_ID_INVALID");

  const updateSql = [
    "UPDATE monitors",
    "SET last_checked_at = ?,",
    "    next_check_at = ?,",
    "    consecutive_failures = CASE WHEN ? = 1 THEN 0 ELSE consecutive_failures + 1 END,",
    "    check_lease_token = NULL,",
    "    check_lease_until = NULL",
    "WHERE id = ? AND check_lease_token = ?"
  ].join("\n");
  const insertSql = [
    "INSERT INTO monitor_checks",
    "(id, monitor_id, checked_at, is_up, status_code, response_time_ms, error_code)",
    "SELECT ?, ?, ?, ?, ?, ?, ? WHERE changes() = 1"
  ].join("\n");

  const results = await db.batch([
    db.prepare(updateSql).bind(checkedAt.sql, nextCheckAt.sql, input.isUp ? 1 : 0, input.monitorId, input.leaseToken),
    db.prepare(insertSql).bind(checkId, input.monitorId, checkedAt.sql, input.isUp ? 1 : 0,
      input.statusCode, input.responseTimeMs, errorCode)
  ]);

  return (results[0]?.meta?.changes ?? 0) === 1 &&
    (results[1]?.meta?.changes ?? 0) === 1;
}
