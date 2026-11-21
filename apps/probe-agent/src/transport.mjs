import { isIP } from "node:net";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";

export const MAX_RESPONSE_BYTES = 64 * 1024;
export const MAX_RESPONSE_HEADER_BYTES = 16 * 1024;

export function createPinnedLookup(address) {
  const family = isIP(address);
  if (family !== 4 && family !== 6) throw new Error("PINNED_ADDRESS_INVALID");
  return (_hostname, options, callback) => {
    if (typeof options === "function") {
      callback = options;
      options = {};
    }
    const requestedFamily = options?.family === "IPv4" ? 4 : options?.family === "IPv6" ? 6 : options?.family || 0;
    if (requestedFamily && requestedFamily !== family) {
      callback(new Error("PINNED_ADDRESS_FAMILY_MISMATCH"));
      return;
    }
    if (options && options.all) callback(null, [{ address, family }]);
    else callback(null, address, family);
  };
}

export function buildPinnedRequestOptions(url, address, options = {}) {
  const family = isIP(address);
  if (family !== 4 && family !== 6) throw new Error("PINNED_ADDRESS_INVALID");
  const hostname = url.hostname.replace(/^\[|\]$/g, "");
  const isTls = url.protocol === "https:";
  return {
    protocol: url.protocol,
    hostname,
    port: Number(url.port || (isTls ? 443 : 80)),
    path: `${url.pathname || "/"}${url.search}`,
    method: options.method === "HEAD" ? "HEAD" : "GET",
    agent: false,
    lookup: createPinnedLookup(address),
    ...(isTls && isIP(hostname) === 0 ? { servername: hostname } : {}),
    ...(isTls ? { rejectUnauthorized: true } : {}),
    maxHeaderSize: MAX_RESPONSE_HEADER_BYTES,
    headers: {
      "user-agent": "ZetuWatch-Probe/0.1",
      accept: "*/*",
      connection: "close"
    }
  };
}

export function requestPinned(url, address, options = {}) {
  const timeoutMs = options.timeoutMs ?? 5_000;
  const maxResponseBytes = options.maxResponseBytes ?? MAX_RESPONSE_BYTES;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) {
    return Promise.reject(new Error("PROBE_TIMEOUT_INVALID"));
  }
  if (!Number.isInteger(maxResponseBytes) || maxResponseBytes < 1 || maxResponseBytes > MAX_RESPONSE_BYTES) {
    return Promise.reject(new Error("PROBE_RESPONSE_LIMIT_INVALID"));
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return Promise.reject(new Error("PROBE_PROTOCOL_NOT_ALLOWED"));
  }

  return new Promise((resolve, reject) => {
    const requestFn = url.protocol === "https:" ? httpsRequest : httpRequest;
    const request = requestFn(buildPinnedRequestOptions(url, address, options), response => {
      const statusCode = Number(response.statusCode || 0);
      const location = response.headers.location;
      if (statusCode >= 300 && statusCode < 400 && typeof location === "string") {
        if (location.length > 2_048) {
          response.destroy();
          finishError(new Error("REDIRECT_LOCATION_TOO_LARGE"));
          return;
        }
        response.destroy();
        finishResolve({ statusCode, location });
        return;
      }

      const contentLength = response.headers["content-length"];
      if (typeof contentLength === "string" && /^\d+$/.test(contentLength) && Number(contentLength) > maxResponseBytes) {
        response.destroy();
        finishError(new Error("RESPONSE_TOO_LARGE"));
        return;
      }

      let received = 0;
      let tooLarge = false;
      response.on("data", chunk => {
        received += chunk.length;
        if (received > maxResponseBytes) {
          tooLarge = true;
          response.destroy(new Error("RESPONSE_TOO_LARGE"));
        }
      });
      response.on("end", () => finishResolve({ statusCode, location: null }));
      response.on("error", error => finishError(error));
      response.on("aborted", () => finishError(new Error(tooLarge ? "RESPONSE_TOO_LARGE" : "RESPONSE_ABORTED")));
    });

    let settled = false;
    const timer = setTimeout(() => request.destroy(new Error("PROBE_TIMEOUT")), timeoutMs);
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
    request.on("error", error => finishError(error));
    request.end();
  });
}
