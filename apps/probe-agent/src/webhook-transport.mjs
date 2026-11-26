import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import { assertPublicDnsAnswers } from "../../../packages/monitoring-core/src/ip-address.mjs";
import { createPinnedLookup, MAX_RESPONSE_HEADER_BYTES } from "./transport.mjs";

export const MAX_WEBHOOK_REQUEST_BYTES = 256 * 1024;
export const MAX_WEBHOOK_RESPONSE_BYTES = 8 * 1024;
export const MAX_WEBHOOK_RESPONSE_HEADER_BYTES = MAX_RESPONSE_HEADER_BYTES;
export const MAX_WEBHOOK_TIMEOUT_MS = 15_000;

function parseRetryAfter(value, nowMs) {
  if (typeof value !== "string" || value.length > 128) return null;
  const trimmed = value.trim();
  if (/^\d{1,10}$/.test(trimmed)) {
    const seconds = Number(trimmed);
    return Number.isSafeInteger(seconds) && seconds > 0 ? Math.min(21_600, seconds) : null;
  }
  const timestamp = Date.parse(trimmed);
  if (!Number.isFinite(timestamp)) return null;
  const seconds = Math.ceil((timestamp - nowMs) / 1000);
  return seconds > 0 ? Math.min(21_600, seconds) : null;
}

export function buildPinnedWebhookRequestOptions(url, address, options = {}) {
  const family = isIP(address);
  if (family !== 4 && family !== 6) throw new Error("PINNED_ADDRESS_INVALID");
  try { assertPublicDnsAnswers([address]); } catch { throw new Error("PINNED_ADDRESS_NOT_PUBLIC"); }
  if (!(url instanceof URL) || url.protocol !== "https:" || url.username || url.password ||
      url.hash || (url.port && url.port !== "443")) {
    throw new Error("WEBHOOK_DESTINATION_INVALID");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  if (!hostname || isIP(hostname) !== 0) throw new Error("WEBHOOK_HOST_INVALID");
  const body = options.body;
  if (!Buffer.isBuffer(body) || body.length < 1 || body.length > MAX_WEBHOOK_REQUEST_BYTES) {
    throw new Error("WEBHOOK_PAYLOAD_INVALID");
  }
  const eventId = options.eventId;
  const signatureHeader = options.signatureHeader;
  if (typeof eventId !== "string" || !/^[a-f0-9-]{32,36}$/i.test(eventId) ||
      typeof signatureHeader !== "string" || !/^t=\d{10},v1=[a-f0-9]{64}$/.test(signatureHeader)) {
    throw new Error("WEBHOOK_HEADERS_INVALID");
  }
  return {
    protocol: "https:",
    hostname,
    port: 443,
    path: (url.pathname || "/") + url.search,
    method: "POST",
    agent: false,
    lookup: createPinnedLookup(address),
    servername: hostname,
    rejectUnauthorized: true,
    maxHeaderSize: MAX_WEBHOOK_RESPONSE_HEADER_BYTES,
    headers: {
      "user-agent": "ZetuWatch-Webhook/0.1",
      accept: "application/json, */*;q=0.5",
      "content-type": "application/json; charset=utf-8",
      "content-length": String(body.length),
      "x-zetuwatch-event-id": eventId,
      "x-zetuwatch-signature": signatureHeader,
      connection: "close"
    }
  };
}

/**
 * Send one HTTPS POST to an already validated DNS-pinned address. Redirects
 * are never followed. Response bodies are discarded and strictly bounded.
 */
export function requestWebhookPinned(url, address, options = {}) {
  const timeoutMs = options.timeoutMs ?? 10_000;
  const body = options.body;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > MAX_WEBHOOK_TIMEOUT_MS) {
    return Promise.reject(new Error("WEBHOOK_TIMEOUT_INVALID"));
  }
  let requestOptions;
  try { requestOptions = buildPinnedWebhookRequestOptions(url, address, options); }
  catch (error) { return Promise.reject(error); }

  return new Promise((resolve, reject) => {
    let settled = false;
    let received = 0;
    let timer;
    const finishResolve = value => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const finishError = error => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    };
    const request = httpsRequest(requestOptions, response => {
      response.on("error", error => finishError(error));
      response.on("aborted", () => finishError(new Error("WEBHOOK_RESPONSE_ABORTED")));
      const statusCode = Number(response.statusCode || 0);
      const contentLength = response.headers["content-length"];
      if (typeof contentLength === "string" && /^\d+$/.test(contentLength) &&
          Number(contentLength) > MAX_WEBHOOK_RESPONSE_BYTES) {
        response.destroy(new Error("WEBHOOK_RESPONSE_TOO_LARGE"));
        finishError(new Error("WEBHOOK_RESPONSE_TOO_LARGE"));
        return;
      }
      const retryAfterSeconds = parseRetryAfter(response.headers["retry-after"], Date.now());
      response.on("data", chunk => {
        received += chunk.length;
        if (received > MAX_WEBHOOK_RESPONSE_BYTES) {
          response.destroy(new Error("WEBHOOK_RESPONSE_TOO_LARGE"));
          finishError(new Error("WEBHOOK_RESPONSE_TOO_LARGE"));
        }
      });
      response.on("end", () => finishResolve({ statusCode, retryAfterSeconds }));
    });
    timer = setTimeout(() => request.destroy(new Error("WEBHOOK_TIMEOUT")), timeoutMs);
    request.on("error", error => finishError(error));
    request.end(body);
  });
}

export { parseRetryAfter };
