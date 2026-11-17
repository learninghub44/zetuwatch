import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { pathToFileURL } from "node:url";
import { runProbe, normalizeProbeInput } from "./runner.mjs";

const MAX_BODY_BYTES = 16 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 60;
const NONCE_TTL_MS = 5 * 60 * 1000;
const MAX_NONCES = 10_000;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 300;
const MAX_ACTIVE_PROBES = 20;

function sendJson(response, status, body) {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "connection": "close"
  });
  response.end(JSON.stringify(body));
}

function canonicalMessage(timestamp, nonce, body) {
  const digest = createHash("sha256").update(body).digest("hex");
  return `v1\n${timestamp}\n${nonce}\n${digest}`;
}

export function signProbeRequest(secret, timestamp, nonce, body) {
  return createHmac("sha256", secret).update(canonicalMessage(timestamp, nonce, body)).digest("hex");
}

function validSignature(secret, timestamp, nonce, body, received) {
  if (typeof received !== "string" || !/^[a-f0-9]{64}$/.test(received)) return false;
  const expected = Buffer.from(signProbeRequest(secret, timestamp, nonce, body), "hex");
  const actual = Buffer.from(received, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function readBody(request, maxBytes) {
  return new Promise((resolve, reject) => {
    const declared = request.headers["content-length"];
    if (typeof declared === "string" && /^\d+$/.test(declared) && Number(declared) > maxBytes) {
      request.resume();
      reject(new Error("BODY_TOO_LARGE"));
      return;
    }
    const chunks = [];
    let total = 0;
    let exceeded = false;
    request.on("data", chunk => {
      if (exceeded) return;
      total += chunk.length;
      if (total > maxBytes) {
        exceeded = true;
        chunks.length = 0;
        return;
      }
      chunks.push(chunk);
    });
    request.on("end", () => {
      if (exceeded) reject(new Error("BODY_TOO_LARGE"));
      else resolve(Buffer.concat(chunks).toString("utf8"));
    });
    request.on("error", () => reject(new Error("BODY_READ_FAILED")));
    request.on("aborted", () => reject(new Error("BODY_READ_FAILED")));
  });
}

function createRateLimiter() {
  const buckets = new Map();
  return ip => {
    const now = Date.now();
    const current = buckets.get(ip);
    if (!current || current.startedAt + RATE_WINDOW_MS <= now) {
      buckets.set(ip, { startedAt: now, count: 1 });
      if (buckets.size > 5_000) {
        for (const [key, value] of buckets) {
          if (value.startedAt + RATE_WINDOW_MS <= now) buckets.delete(key);
        }
      }
      return true;
    }
    current.count += 1;
    return current.count <= RATE_LIMIT;
  };
}

export function createProbeHandler(options = {}) {
  const secret = options.secret;
  if (typeof secret !== "string" || new TextEncoder().encode(secret).byteLength < 32) {
    throw new Error("PROBE_SHARED_SECRET_REQUIRED");
  }
  const probe = options.probe ?? runProbe;
  const now = options.now ?? (() => Date.now());
  const nonces = new Map();
  const allowRate = createRateLimiter();
  let active = 0;

  return async (request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      sendJson(response, 200, { status: "ok" });
      return;
    }
    if (request.method !== "POST" || request.url !== "/v1/probe") {
      sendJson(response, 404, { error: "NOT_FOUND" });
      return;
    }

    const ip = request.socket?.remoteAddress || "unknown";
    if (!allowRate(ip)) {
      sendJson(response, 429, { error: "RATE_LIMITED" });
      return;
    }
    if (active >= MAX_ACTIVE_PROBES) {
      sendJson(response, 429, { error: "CAPACITY_EXCEEDED" });
      return;
    }

    // Reserve capacity before reading the body so slow clients cannot create
    // an unbounded number of concurrent in-flight request bodies.
    active += 1;
    try {
      const contentType = request.headers["content-type"] || "";
      const contentEncoding = request.headers["content-encoding"] || "identity";
      if (!/^application\/json(?:\s*;|$)/i.test(contentType) || contentEncoding !== "identity") {
        sendJson(response, 415, { error: "UNSUPPORTED_MEDIA_TYPE" });
        return;
      }
      let body;
      try { body = await readBody(request, MAX_BODY_BYTES); }
      catch (error) {
        sendJson(response, error?.message === "BODY_TOO_LARGE" ? 413 : 400, { error: error?.message === "BODY_TOO_LARGE" ? "BODY_TOO_LARGE" : "INVALID_REQUEST" });
        return;
      }

      const timestampText = request.headers["x-zw-timestamp"];
      const nonce = request.headers["x-zw-nonce"];
      const signature = request.headers["x-zw-signature"];
      const timestamp = typeof timestampText === "string" && /^\d{10}$/.test(timestampText) ? Number(timestampText) : NaN;
      const currentSeconds = Math.floor(now() / 1000);
      if (!Number.isSafeInteger(timestamp) || Math.abs(currentSeconds - timestamp) > MAX_CLOCK_SKEW_SECONDS ||
          typeof nonce !== "string" || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) ||
          !validSignature(secret, timestampText, nonce, body, signature)) {
        sendJson(response, 401, { error: "UNAUTHORIZED" });
        return;
      }

      for (const [key, expiresAt] of nonces) {
        if (expiresAt <= now()) nonces.delete(key);
      }
      if (nonces.has(nonce)) {
        sendJson(response, 409, { error: "REPLAY_REJECTED" });
        return;
      }
      if (nonces.size >= MAX_NONCES) {
        sendJson(response, 503, { error: "REPLAY_GUARD_FULL" });
        return;
      }
      nonces.set(nonce, now() + NONCE_TTL_MS);

      let job;
      try { job = normalizeProbeInput(JSON.parse(body)); }
      catch { sendJson(response, 400, { error: "INVALID_PROBE_JOB" }); return; }

      const result = await probe(job);
      sendJson(response, 200, { result });
    } catch {
      if (!response.headersSent) sendJson(response, 502, { error: "PROBE_FAILED" });
      else response.destroy();
    } finally {
      active -= 1;
    }
  };
}

export function startServer(env = process.env) {
  const certPath = env.PROBE_TLS_CERT_FILE;
  const keyPath = env.PROBE_TLS_KEY_FILE;
  if (!certPath || !keyPath) throw new Error("PROBE_TLS_CERT_FILE_AND_KEY_REQUIRED");
  const handler = createProbeHandler({ secret: env.PROBE_SHARED_SECRET });
  const server = createHttpsServer({
    cert: readFileSync(certPath),
    key: readFileSync(keyPath),
    maxHeaderSize: 8 * 1024,
    requestTimeout: 15_000,
    headersTimeout: 5_000,
    keepAliveTimeout: 5_000,
    maxRequestsPerSocket: 100
  }, (request, response) => {
    void handler(request, response);
  });
  const port = Number(env.PROBE_PORT || 8788);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) throw new Error("PROBE_PORT_INVALID");
  const host = env.PROBE_HOST || "0.0.0.0";
  server.listen(port, host);
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  startServer();
}
