import { Resolver } from "node:dns/promises";
import { assertPublicDnsAnswers } from "../../../packages/monitoring-core/src/ip-address.mjs";

const DNS_TIMEOUT_MS = 2_500;

/**
 * Resolve A and AAAA concurrently with a single bounded deadline.
 * If the deadline expires, cancel the resolver so timed-out queries do not
 * continue running outside the probe agent's active-request accounting.
 */
export async function resolveWithResolver(hostname, timeoutMs, resolver) {
  if (typeof hostname !== "string" || !hostname || hostname.length > 253) {
    throw new Error("DNS_HOST_INVALID");
  }
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > DNS_TIMEOUT_MS) {
    throw new Error("DNS_TIMEOUT_INVALID");
  }

  const pending = Promise.allSettled([
    resolver.resolve4(hostname),
    resolver.resolve6(hostname)
  ]);
  let timer;
  let timedOut = false;
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      timedOut = true;
      try { resolver.cancel(); } catch { /* the deadline still has to reject */ }
      reject(new Error("DNS_TIMEOUT"));
    }, timeoutMs);
  });

  try {
    const results = await Promise.race([pending, deadline]);
    const addresses = [];
    for (const result of results) {
      if (result.status === "fulfilled") addresses.push(...result.value);
      else if (!(result.reason && typeof result.reason === "object" && result.reason.code === "ENODATA")) {
        throw new Error("DNS_LOOKUP_FAILED");
      }
    }
    return assertPublicDnsAnswers(addresses);
  } catch (error) {
    if (timedOut) throw new Error("DNS_TIMEOUT");
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

/** Resolve all A/AAAA records using an isolated, cancellable Node resolver. */
export async function resolvePublicAddresses(hostname, timeoutMs = DNS_TIMEOUT_MS) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > DNS_TIMEOUT_MS) {
    throw new Error("DNS_TIMEOUT_INVALID");
  }
  const resolver = new Resolver({ timeout: timeoutMs, tries: 1 });
  return resolveWithResolver(hostname, timeoutMs, resolver);
}
