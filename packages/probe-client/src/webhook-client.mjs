import { validateProbeAgentEndpoint, signProbePayload } from "./client.mjs";
const encoder = new TextEncoder();
const MAX_RESPONSE_BYTES = 4 * 1024;
const MAX_WEBHOOK_PAYLOAD_BYTES = 256 * 1024;
const WEBHOOK_EVENT_ID_PATTERN = /^[a-f0-9-]{32,36}$/i;
const WEBHOOK_SIGNATURE_PATTERN = /^t=(\d{10}),v1=[a-f0-9]{64}$/;
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
async function readLimitedJson(response) {
  if (!response.body) throw new Error("WEBHOOK_AGENT_INVALID_RESPONSE");
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const item = await reader.read();
      if (item.done) break;
      total += item.value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel().catch(() => undefined);
        throw new Error("WEBHOOK_AGENT_RESPONSE_TOO_LARGE");
      }
      chunks.push(item.value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
  catch { throw new Error("WEBHOOK_AGENT_INVALID_RESPONSE"); }
}
function normalizeWebhookJob(input, nowMs) {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error("WEBHOOK_JOB_INVALID");
  const allowed = new Set(["destinationUrl", "eventId", "payload", "signatureHeader"]);
  if (Object.keys(input).some(key => !allowed.has(key))) throw new Error("WEBHOOK_JOB_INVALID");
  if (typeof input.destinationUrl !== "string" || input.destinationUrl.length < 1 ||
      input.destinationUrl.length > 2_048 || /[\u0000-\u001f\u007f]/.test(input.destinationUrl)) {
    throw new Error("WEBHOOK_DESTINATION_INVALID");
  }
  let destination;
  try { destination = new URL(input.destinationUrl); }
  catch { throw new Error("WEBHOOK_DESTINATION_INVALID"); }
  const host = destination.hostname.replace(/^\[|\]$/g, "");
  if (destination.protocol !== "https:" || destination.username || destination.password ||
      destination.hash || (destination.port && destination.port !== "443") ||
      host.includes(":") || /^\d+(?:\.\d+){0,3}$/.test(host) || !host.includes(".")) {
    throw new Error("WEBHOOK_DESTINATION_INVALID");
  }
  if (typeof input.eventId !== "string" || !WEBHOOK_EVENT_ID_PATTERN.test(input.eventId)) {
    throw new Error("WEBHOOK_EVENT_ID_INVALID");
  }
  if (typeof input.payload !== "string") throw new Error("WEBHOOK_PAYLOAD_INVALID");
  const payloadBytes = encoder.encode(input.payload);
  if (payloadBytes.byteLength < 1 || payloadBytes.byteLength > MAX_WEBHOOK_PAYLOAD_BYTES) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  let parsed;
  try { parsed = JSON.parse(input.payload); }
  catch { throw new Error("WEBHOOK_PAYLOAD_INVALID"); }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) || parsed.eventId !== input.eventId) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  const signatureMatch = typeof input.signatureHeader === "string"
    ? WEBHOOK_SIGNATURE_PATTERN.exec(input.signatureHeader)
    : null;
  if (!signatureMatch) throw new Error("WEBHOOK_SIGNATURE_INVALID");
  if (!Number.isSafeInteger(nowMs) ||
      Math.abs(Math.floor(nowMs / 1000) - Number(signatureMatch[1])) > 300) {
    throw new Error("WEBHOOK_SIGNATURE_STALE");
  }
  return {
    destinationUrl: destination.href,
    eventId: input.eventId,
    payloadBase64: toBase64Url(payloadBytes),
    signatureHeader: input.signatureHeader
  };
}

/** Send one bounded webhook job through the authenticated DNS-pinning agent. */
export async function sendWebhookJob(endpoint, secret, input, options = {}) {
  const probeEndpoint = validateProbeAgentEndpoint(endpoint);
  const target = new URL("/v1/webhook", probeEndpoint.origin);
  const fetcher = options.fetcher ?? fetch;
  const now = options.now ?? Date.now;
  const job = normalizeWebhookJob(input, now());
  const timestamp = String(Math.floor(now() / 1000));
  const nonce = toBase64Url(crypto.getRandomValues(new Uint8Array(24)));
  const body = JSON.stringify(job);
  const signature = await signProbePayload(secret, timestamp, nonce, body);
  const requestTimeoutMs = options.requestTimeoutMs ?? 20_000;
  if (!Number.isInteger(requestTimeoutMs) || requestTimeoutMs < 1_000 || requestTimeoutMs > 25_000) {
    throw new Error("WEBHOOK_AGENT_TIMEOUT_INVALID");
  }
  let response;
  try {
    response = await fetcher(target.href, {
      method: "POST",
      redirect: "error",
      cache: "no-store",
      credentials: "omit",
      signal: AbortSignal.timeout(requestTimeoutMs),
      headers: {
        "content-type": "application/json",
        "x-zw-timestamp": timestamp,
        "x-zw-nonce": nonce,
        "x-zw-signature": signature
      },
      body
    });
  } catch { throw new Error("WEBHOOK_AGENT_UNAVAILABLE"); }
  if (!response.ok) throw new Error(response.status === 401 || response.status === 409
    ? "WEBHOOK_AGENT_AUTH_FAILED" : "WEBHOOK_AGENT_UNAVAILABLE");
  if (!(response.headers.get("content-type") || "").toLowerCase().includes("application/json")) {
    throw new Error("WEBHOOK_AGENT_INVALID_RESPONSE");
  }
  const payload = await readLimitedJson(response);
  const result = payload?.result;
  if (!result || typeof result.delivered !== "boolean" ||
      !(result.responseStatus === null || (Number.isInteger(result.responseStatus) && result.responseStatus >= 100 && result.responseStatus <= 599)) ||
      !(result.errorCode === null || (typeof result.errorCode === "string" && /^[A-Z_]{1,48}$/.test(result.errorCode))) ||
      !(result.retryAfterSeconds === null || (Number.isInteger(result.retryAfterSeconds) && result.retryAfterSeconds >= 1 && result.retryAfterSeconds <= 21_600)) ||
      (result.delivered && (result.responseStatus === null || result.responseStatus < 200 || result.responseStatus > 299 || result.errorCode !== null)) ||
      (!result.delivered && result.errorCode === null)) {
    throw new Error("WEBHOOK_AGENT_INVALID_RESPONSE");
  }
  return result;
}
