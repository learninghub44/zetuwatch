import { resolve4, resolve6 } from "node:dns/promises";
import { assertPublicDnsAnswers } from "../../../packages/monitoring-core/src/ip-address.mjs";

const DNS_TIMEOUT_MS = 2_500;

function withTimeout(promise, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("DNS_TIMEOUT")), timeoutMs);
    promise.then(resolve, reject).finally(() => clearTimeout(timer));
  });
}

function isNoData(error) {
  return error && typeof error === "object" && error.code === "ENODATA";
}

export async function resolvePublicAddresses(hostname, timeoutMs = DNS_TIMEOUT_MS) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > DNS_TIMEOUT_MS) {
    throw new Error("DNS_TIMEOUT_INVALID");
  }
  const results = await withTimeout(Promise.allSettled([
    resolve4(hostname),
    resolve6(hostname)
  ]), timeoutMs);
  const addresses = [];
  for (const result of results) {
    if (result.status === "fulfilled") addresses.push(...result.value);
    else if (!isNoData(result.reason)) throw new Error("DNS_LOOKUP_FAILED");
  }
  return assertPublicDnsAnswers(addresses);
}
