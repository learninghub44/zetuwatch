import { isIP } from "node:net";
import { assertPublicDnsAnswers, isIpv4Address } from "../../../packages/monitoring-core/src/ip-address.mjs";
import { validateMonitorUrl, isBlockedHostname } from "../../../packages/monitoring-core/src/url-safety.mjs";
import { resolvePublicAddresses } from "./dns-resolver.mjs";
import { requestWebhookPinned, MAX_WEBHOOK_REQUEST_BYTES, MAX_WEBHOOK_TIMEOUT_MS } from "./webhook-transport.mjs";

const MAX_DNS_TIMEOUT_MS = 2_500;
const MAX_SIGNATURE_AGE_SECONDS = 300;
const SIGNATURE_PATTERN = /^t=(\d{10}),v1=([a-f0-9]{64})$/;
const EVENT_ID_PATTERN = /^[a-f0-9-]{32,36}$/i;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
function decodePayload(value, eventId) {
  if (typeof value !== "string" || value.length < 1 || value.length > 350_000 || !BASE64URL_PATTERN.test(value)) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length < 2 || bytes.length > MAX_WEBHOOK_REQUEST_BYTES || bytes.toString("base64url") !== value) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); }
  catch { throw new Error("WEBHOOK_PAYLOAD_INVALID"); }
  let parsed;
  try { parsed = JSON.parse(text); }
  catch { throw new Error("WEBHOOK_PAYLOAD_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.eventId !== eventId) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  return bytes;
}

function validateWebhookDestination(input) {
  const destination = validateMonitorUrl(input);
  const hostname = destination.hostname.toLowerCase().replace(/\.$/, "");
  if (destination.protocol !== "https:" || (destination.port && destination.port !== "443") ||
      destination.hash || isIP(hostname.replace(/^\[|\]$/g, "")) !== 0 || isBlockedHostname(hostname)) {
    throw new Error("WEBHOOK_DESTINATION_INVALID");
  }
  return destination;
}

export function normalizeWebhookInput(input, nowMs = Date.now()) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("WEBHOOK_JOB_INVALID");
  const allowed = new Set(["destinationUrl", "eventId", "payloadBase64", "signatureHeader"]);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error("WEBHOOK_JOB_INVALID");
  if (typeof input.destinationUrl !== "string" || input.destinationUrl.length < 1 ||
      input.destinationUrl.length > 2_048 || /[\u0000-\u001f\u007f]/.test(input.destinationUrl)) {
    throw new Error("WEBHOOK_DESTINATION_INVALID");
  }
  let destination;
  try { destination = validateWebhookDestination(input.destinationUrl); }
  catch { throw new Error("WEBHOOK_DESTINATION_INVALID"); }
  if (typeof input.eventId !== "string" || !EVENT_ID_PATTERN.test(input.eventId)) {
    throw new Error("WEBHOOK_EVENT_ID_INVALID");
  }
  const signature = typeof input.signatureHeader === "string" ? SIGNATURE_PATTERN.exec(input.signatureHeader) : null;
  if (!signature) throw new Error("WEBHOOK_SIGNATURE_INVALID");
  const timestamp = Number(signature[1]);
  const nowSeconds = Math.floor(nowMs / 1000);
  if (!Number.isSafeInteger(nowSeconds) || Math.abs(nowSeconds - timestamp) > MAX_SIGNATURE_AGE_SECONDS) {
    throw new Error("WEBHOOK_SIGNATURE_STALE");
  }
  const body = decodePayload(input.payloadBase64, input.eventId);
  return {
    destinationUrl: destination.href,
    eventId: input.eventId,
    body,
    signatureHeader: input.signatureHeader
  };
}

function chooseAddress(addresses) {
  const safe = assertPublicDnsAnswers(addresses);
  return safe.find(isIpv4Address) || safe[0];
}

function classifyError(error) {
  const message = error instanceof Error ? error.message : "";
  const code = error && typeof error === "object" && typeof error.code === "string" ? error.code : "";
  if (message === "WEBHOOK_TIMEOUT" || message === "DNS_TIMEOUT") return "TIMEOUT";
  if (message === "DNS_NON_PUBLIC_ADDRESS" || message === "DNS_TOO_MANY_ADDRESSES") return "TARGET_NOT_ALLOWED";
  if (message.startsWith("WEBHOOK_DESTINATION") || message.startsWith("WEBHOOK_HOST")) return "TARGET_NOT_ALLOWED";
  if (message.startsWith("DNS_")) return "DNS_FAILURE";
  if (code.startsWith("ERR_TLS") || code.startsWith("CERT_") || code.startsWith("ERR_SSL") ||
      message.toUpperCase().includes("CERT") || message.includes("TLS") || message.includes("SELF_SIGNED")) return "TLS_ERROR";
  if (message === "WEBHOOK_RESPONSE_TOO_LARGE") return "RESPONSE_TOO_LARGE";
  return "NETWORK_ERROR";
}

function result(errorCode, responseStatus = null, retryAfterSeconds = null) {
  return { delivered: false, responseStatus, errorCode, retryAfterSeconds };
}

/**
 * Deliver one signed event to one HTTPS destination. Every attempt resolves all
 * A/AAAA records, rejects any non-public answer, pins one validated IP, retains
 * the original hostname for SNI/certificate verification and never follows a
 * redirect. The caller owns durable leases and retries.
 */
export async function runWebhook(job, adapters = {}) {
  const now = adapters.now ?? Date.now;
  const startedAt = now();
  const resolver = adapters.resolver ?? resolvePublicAddresses;
  const requester = adapters.requester ?? requestWebhookPinned;
  if (!job || typeof job !== "object" || !Buffer.isBuffer(job.body) ||
      job.body.length < 1 || job.body.length > MAX_WEBHOOK_REQUEST_BYTES ||
      typeof job.eventId !== "string" || !EVENT_ID_PATTERN.test(job.eventId) ||
      typeof job.signatureHeader !== "string") {
    return result("REQUEST_INVALID");
  }
  const signatureMatch = SIGNATURE_PATTERN.exec(job.signatureHeader);
  const nowSeconds = Math.floor(startedAt / 1000);
  if (!signatureMatch || !Number.isSafeInteger(nowSeconds) ||
      Math.abs(nowSeconds - Number(signatureMatch[1])) > MAX_SIGNATURE_AGE_SECONDS) {
    return result("REQUEST_INVALID");
  }
  let destination;
  try { destination = validateWebhookDestination(job.destinationUrl); }
  catch { return result("TARGET_NOT_ALLOWED"); }

  const elapsed = Math.max(0, now() - startedAt);
  const remainingForDns = MAX_WEBHOOK_TIMEOUT_MS - elapsed;
  if (remainingForDns < 100) return result("TIMEOUT");

  let address;
  try {
    const hostname = destination.hostname.replace(/^\[|\]$/g, "");
    const candidates = await resolver(hostname, Math.min(MAX_DNS_TIMEOUT_MS, remainingForDns));
    address = chooseAddress(candidates);
  } catch (error) {
    return result(classifyError(error));
  }

  const remaining = MAX_WEBHOOK_TIMEOUT_MS - Math.max(0, now() - startedAt);
  if (remaining < 100) return result("TIMEOUT");
  try {
    const response = await requester(destination, address, {
      body: job.body,
      eventId: job.eventId,
      signatureHeader: job.signatureHeader,
      timeoutMs: Math.min(remaining, MAX_WEBHOOK_TIMEOUT_MS),
      maxResponseBytes: 8 * 1024
    });
    if (!Number.isInteger(response.statusCode) || response.statusCode < 100 || response.statusCode > 599) {
      return result("REMOTE_RESPONSE_INVALID");
    }
    if (response.statusCode >= 200 && response.statusCode <= 299) {
      return { delivered: true, responseStatus: response.statusCode, errorCode: null, retryAfterSeconds: null };
    }
    if (response.statusCode >= 300 && response.statusCode <= 399) {
      return result("REDIRECT_BLOCKED", response.statusCode);
    }
    if (response.statusCode === 429) {
      return result("REMOTE_RATE_LIMITED", response.statusCode, response.retryAfterSeconds ?? null);
    }
    if (response.statusCode >= 500) {
      return result("REMOTE_SERVER_ERROR", response.statusCode, response.retryAfterSeconds ?? null);
    }
    return result("REMOTE_REJECTED", response.statusCode);
  } catch (error) {
    return result(classifyError(error), null);
  }
}
