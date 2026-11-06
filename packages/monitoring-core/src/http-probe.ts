import { validateMonitorUrl } from "./url-safety";

export interface HttpProbeResult {
  isUp: boolean;
  statusCode: number | null;
  responseTimeMs: number;
  errorCode: string | null;
}

export async function runHttpProbe(
  target: string,
  method = "GET",
  expectedStatus = 200,
  timeoutMs = 10_000
): Promise<HttpProbeResult> {
  const url = validateMonitorUrl(target);
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), Math.min(Math.max(timeoutMs, 1000), 30_000));

  try {
    const response = await fetch(url, {
      method,
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "ZetuWatch-Monitor/0.1" }
    });
    return {
      isUp: response.status === expectedStatus,
      statusCode: response.status,
      responseTimeMs: Date.now() - started,
      errorCode: response.status >= 300 && response.status < 400 ? "REDIRECT_NOT_FOLLOWED" : null
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
