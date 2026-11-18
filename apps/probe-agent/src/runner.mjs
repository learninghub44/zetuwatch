import { assertPublicDnsAnswers, isIpv4Address } from "../../../packages/monitoring-core/src/ip-address.mjs";
import { validateMonitorUrl } from "../../../packages/monitoring-core/src/url-safety.mjs";
import { resolvePublicAddresses } from "./dns-resolver.mjs";
import { requestPinned, MAX_RESPONSE_BYTES } from "./transport.mjs";

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 3;

export function normalizeProbeInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("PROBE_JOB_INVALID");
  const allowed = new Set(["targetUrl", "method", "expectedStatus", "timeoutMs", "maxRedirects"]);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error("PROBE_JOB_INVALID");
  const method = input.method ?? "GET";
  const expectedStatus = input.expectedStatus ?? 200;
  const timeoutMs = input.timeoutMs ?? 5_000;
  const maxRedirects = input.maxRedirects ?? 0;
  if (method !== "GET" && method !== "HEAD") throw new Error("PROBE_METHOD_NOT_ALLOWED");
  if (!Number.isInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599) throw new Error("PROBE_STATUS_INVALID");
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1_000 || timeoutMs > MAX_TIMEOUT_MS) throw new Error("PROBE_TIMEOUT_INVALID");
  if (!Number.isInteger(maxRedirects) || maxRedirects < 0 || maxRedirects > MAX_REDIRECTS) throw new Error("PROBE_REDIRECT_LIMIT_INVALID");
  const target = validateMonitorUrl(input.targetUrl);
  return { targetUrl: target.href, method, expectedStatus, timeoutMs, maxRedirects };
}

function chooseAddress(addresses) {
  const safe = assertPublicDnsAnswers(addresses);
  return safe.find(isIpv4Address) || safe[0];
}

function errorCode(error) {
  const message = error instanceof Error ? error.message : "";
  const code = error && typeof error === "object" && typeof error.code === "string" ? error.code : "";
  if (message === "PROBE_TIMEOUT" || message === "DNS_TIMEOUT") return "TIMEOUT";
  if (message === "RESPONSE_TOO_LARGE") return "RESPONSE_TOO_LARGE";
  if (message.startsWith("DNS_")) return "DNS_FAILURE";
  if (code.startsWith("ERR_TLS") || code.startsWith("CERT_") || code.startsWith("ERR_SSL") || message.toUpperCase().includes("CERT") || message.includes("TLS") || message.includes("SELF_SIGNED")) return "TLS_ERROR";
  if (message === "REDIRECT_DOWNGRADE" || message === "REDIRECT_BLOCKED" || message === "REDIRECT_LIMIT" || message === "REDIRECT_NOT_ALLOWED" || message === "REDIRECT_LOOP" || message === "REDIRECT_LOCATION_TOO_LARGE") return message === "REDIRECT_LOCATION_TOO_LARGE" ? "REDIRECT_BLOCKED" : message;
  if (message.startsWith("PROBE_") || message.startsWith("URL_") || message.startsWith("HOST_") || message.startsWith("PORT_") || message.startsWith("IP_") || message === "UNSUPPORTED_PROTOCOL" || message === "INVALID_URL" || message === "PINNED_ADDRESS_INVALID" || message === "PINNED_ADDRESS_FAMILY_MISMATCH") return "TARGET_NOT_ALLOWED";
  return "NETWORK_ERROR";
}

function failure(startedAt, now, code, statusCode = null, redirectCount = 0) {
  return {
    isUp: false,
    statusCode,
    responseTimeMs: Math.max(0, Math.round(now() - startedAt)),
    errorCode: code,
    redirectCount
  };
}

/**
 * Resolve every A/AAAA answer, reject mixed/private answer sets, then pass one
 * exact public IP to a transport that uses a custom lookup callback. Each
 * redirect is parsed, revalidated and independently resolved before a new
 * pinned connection is opened.
 */
export async function runProbe(input, adapters = {}) {
  const now = adapters.now ?? Date.now;
  const startedAt = now();
  let job;
  try { job = normalizeProbeInput(input); }
  catch (error) { return failure(startedAt, now, errorCode(error)); }

  const resolver = adapters.resolver ?? resolvePublicAddresses;
  const requester = adapters.requester ?? requestPinned;
  let currentUrl;
  try { currentUrl = validateMonitorUrl(job.targetUrl); }
  catch (error) { return failure(startedAt, now, errorCode(error)); }
  let redirectCount = 0;
  const visited = new Set();

  while (true) {
    if (visited.has(currentUrl.href)) return failure(startedAt, now, "REDIRECT_LOOP", null, redirectCount);
    visited.add(currentUrl.href);
    const remainingMs = job.timeoutMs - (now() - startedAt);
    if (remainingMs < 100) return failure(startedAt, now, "TIMEOUT", null, redirectCount);

    let pinnedAddress;
    try {
      const hostname = currentUrl.hostname.replace(/^\[|\]$/g, "");
      const candidates = isIpv4Address(hostname)
        ? assertPublicDnsAnswers([hostname])
        : await resolver(hostname, Math.min(2_500, remainingMs));
      pinnedAddress = chooseAddress(candidates);
    } catch (error) {
      return failure(startedAt, now, errorCode(error), null, redirectCount);
    }

    const requestRemainingMs = job.timeoutMs - (now() - startedAt);
    if (requestRemainingMs < 100) return failure(startedAt, now, "TIMEOUT", null, redirectCount);

    let response;
    try {
      response = await requester(currentUrl, pinnedAddress, {
        method: job.method,
        timeoutMs: Math.min(MAX_TIMEOUT_MS, requestRemainingMs),
        maxResponseBytes: MAX_RESPONSE_BYTES
      });
    } catch (error) {
      return failure(startedAt, now, errorCode(error), null, redirectCount);
    }

    if (REDIRECT_STATUSES.has(response.statusCode) && response.location) {
      if (redirectCount >= job.maxRedirects) {
        return failure(startedAt, now, "REDIRECT_LIMIT", response.statusCode, redirectCount);
      }
      let nextUrl;
      try { nextUrl = validateMonitorUrl(new URL(response.location, currentUrl).href); }
      catch { return failure(startedAt, now, "REDIRECT_BLOCKED", response.statusCode, redirectCount); }
      if (currentUrl.protocol === "https:" && nextUrl.protocol !== "https:") {
        return failure(startedAt, now, "REDIRECT_DOWNGRADE", response.statusCode, redirectCount);
      }
      if (visited.has(nextUrl.href)) return failure(startedAt, now, "REDIRECT_LOOP", response.statusCode, redirectCount);
      currentUrl = nextUrl;
      redirectCount += 1;
      continue;
    }

    const isUp = response.statusCode === job.expectedStatus;
    return {
      isUp,
      statusCode: response.statusCode,
      responseTimeMs: Math.max(0, Math.round(now() - startedAt)),
      errorCode: isUp ? null : "HTTP_STATUS_MISMATCH",
      redirectCount
    };
  }
}
