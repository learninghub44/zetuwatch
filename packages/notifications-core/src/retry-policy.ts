export const MAX_WEBHOOK_DELIVERY_ATTEMPTS = 10;
export const WEBHOOK_RETRY_BASE_DELAY_MS = 30_000;
export const WEBHOOK_RETRY_MAX_DELAY_MS = 6 * 60 * 60 * 1000;

/** Network failures and transient HTTP responses may be retried. */
export function isRetryableWebhookStatus(status: number | null): boolean {
  if (status === null) return true;
  if (!Number.isInteger(status) || status < 100 || status > 599) return false;
  return status === 408 ||
    status === 425 ||
    status === 429 ||
    (status >= 500 && status <= 599);
}

/**
 * Calculate a bounded exponential delay with injectable full-range jitter.
 * failedAttempt is the number of attempts that have already failed (1-based).
 */
export function webhookRetryDelayMs(failedAttempt: number, randomValue = 0.5): number {
  if (!Number.isInteger(failedAttempt) ||
      failedAttempt < 1 ||
      failedAttempt > MAX_WEBHOOK_DELIVERY_ATTEMPTS) {
    throw new Error("WEBHOOK_ATTEMPT_INVALID");
  }
  if (!Number.isFinite(randomValue) || randomValue < 0 || randomValue > 1) {
    throw new Error("WEBHOOK_JITTER_INVALID");
  }

  const exponent = Math.min(failedAttempt - 1, 20);
  const exponential = Math.min(
    WEBHOOK_RETRY_MAX_DELAY_MS,
    WEBHOOK_RETRY_BASE_DELAY_MS * (2 ** exponent)
  );
  const jittered = Math.round(exponential * (0.5 + randomValue));
  return Math.min(WEBHOOK_RETRY_MAX_DELAY_MS, jittered);
}

/** Return null when the delivery has exhausted its retry budget. */
export function nextWebhookAttemptAt(
  failedAttempt: number,
  nowMilliseconds = Date.now(),
  randomValue = 0.5
): string | null {
  if (!Number.isInteger(failedAttempt) ||
      failedAttempt < 1 ||
      failedAttempt > MAX_WEBHOOK_DELIVERY_ATTEMPTS) {
    throw new Error("WEBHOOK_ATTEMPT_INVALID");
  }
  if (!Number.isFinite(nowMilliseconds) ||
      nowMilliseconds < -8_640_000_000_000_000 ||
      nowMilliseconds > 8_640_000_000_000_000) {
    throw new Error("WEBHOOK_CLOCK_INVALID");
  }
  if (failedAttempt >= MAX_WEBHOOK_DELIVERY_ATTEMPTS) return null;

  const next = nowMilliseconds + webhookRetryDelayMs(failedAttempt, randomValue);
  if (!Number.isFinite(next) || Math.abs(next) > 8_640_000_000_000_000) {
    throw new Error("WEBHOOK_CLOCK_INVALID");
  }
  return new Date(next).toISOString();
}
