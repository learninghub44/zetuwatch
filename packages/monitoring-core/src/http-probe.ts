import { validateMonitorUrl } from "./url-safety";

export interface HttpProbeResult {
  isUp: boolean;
  statusCode: number | null;
  responseTimeMs: number;
  errorCode: string | null;
}

/**
 * Performs a deliberately small HTTP probe.
 *
 * Redirects are not followed: each redirect destination must be validated by
 * the scheduler before another request is issued. This function accepts only
 * GET/HEAD and never forwards caller-provided headers or credentials.
 */
export async function runHttpProbe(
  target: string,
  method = "GET",
  expectedStatus = 200,
  timeoutMs = 10_000
): Promise<HttpProbeResult> {
  const url = validateMonitorUrl(target);
  const normalizedMethod = method.toUpperCase();
  if (normalizedMethod !== "GET" && normalizedMethod !== "HEAD") {
    throw new Error("METHOD_NOT_ALLOWED");
  }
  if (!Number.isInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599) {
    throw new Error("EXPECTED_STATUS_INVALID");
  }

  const started = Date.now();
  const controller = new AbortController();
  const boundedTimeout = Number.isFinite(timeoutMs)
    ? Math.min(Math.max(timeoutMs, 1_000), 30_000)
    : 10_000;
  const timeout = setTimeout(() => controller.abort(), boundedTimeout);

  try {
    const response = await fetch(url, {
      method: normalizedMethod,
      redirect: "manual",
      cache: "no-store",
      signal: controller.signal,
      headers: { "user-agent": "ZetuWatch-Monitor/0.1" }
    });

    // We measure time-to-headers and discard the body to bound memory use.
    try {
      await response.body?.cancel();
    } catch {
      // A body cancellation failure must not hide the observed HTTP status.
    }

    const isRedirect = response.status >= 300 && response.status < 400;
    return {
      isUp: response.status === expectedStatus,
      statusCode: response.status,
      responseTimeMs: Date.now() - started,
      errorCode: isRedirect ? "REDIRECT_NOT_FOLLOWED" : null
    };
  } catch (error) {
    const isTimeout = error instanceof Error && error.name === "AbortError";
    return {
      isUp: false,
      statusCode: null,
      responseTimeMs: Date.now() - started,
      errorCode: isTimeout ? "TIMEOUT" : "NETWORK_ERROR"
    };
  } finally {
    clearTimeout(timeout);
  }
}
