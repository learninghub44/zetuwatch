import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { isIP } from "node:net";
import { readFileSync } from "node:fs";
import { createServer as createHttpsServer } from "node:https";
import { pathToFileURL } from "node:url";
import { runProbe, normalizeProbeInput } from "./runner.mjs";
import { runWebhook, normalizeWebhookInput } from "./webhook-runner.mjs";

const MAX_BODY_BYTES = 16 * 1024;
const MAX_WEBHOOK_JOB_BYTES = 360 * 1024;
const MAX_CLOCK_SKEW_SECONDS = 60;
const NONCE_TTL_MS = 5 * 60 * 1000;
const MAX_NONCES = 10_000;
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 300;
const MAX_RATE_BUCKETS = 5_000;
const MAX_ACTIVE_EGRESS = 20;

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

export function createDurableNonceClaimer(options = {}) {
  const secret = options.secret;
  if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < 32) {
    throw new Error("PROBE_SHARED_SECRET_REQUIRED");
  }
  let endpoint;
  try { endpoint = new URL(options.url); }
  catch { throw new Error("REPLAY_STORE_URL_INVALID"); }
  const hostname = endpoint.hostname.replace(/^\[|\]$/g, "");
  if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password ||
      endpoint.search || endpoint.hash || endpoint.pathname !== "/internal/probe-agent/replay" ||
      (endpoint.port && endpoint.port !== "443") || isIP(hostname) !== 0 ||
      !hostname.includes(".") || hostname === "localhost" ||
      hostname.endsWith(".localhost") || hostname.endsWith(".local") ||
      hostname.endsWith(".internal") || hostname.endsWith(".test") ||
      hostname.endsWith(".invalid") || hostname.endsWith(".onion")) {
    throw new Error("REPLAY_STORE_URL_INVALID");
  }
  const fetcher = options.fetcher ?? fetch;
  const timeoutMs = options.timeoutMs ?? 3_000;
  if (typeof fetcher !== "function" || !Number.isInteger(timeoutMs) ||
      timeoutMs < 250 || timeoutMs > 5_000) {
    throw new Error("REPLAY_STORE_CONFIG_INVALID");
  }

  return async ({ timestamp, nonce }) => {
    if (typeof timestamp !== "string" || !/^\d{10}$/.test(timestamp) ||
        typeof nonce !== "string" || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) {
      throw new Error("REPLAY_STORE_REQUEST_INVALID");
    }
    const body = JSON.stringify({ nonce });
    const signature = signProbeRequest(secret, timestamp, nonce, body);
    let response;
    try {
      response = await fetcher(endpoint.href, {
        method: "POST",
        redirect: "error",
        cache: "no-store",
        credentials: "omit",
        signal: AbortSignal.timeout(timeoutMs),
        headers: {
          "content-type": "application/json",
          "x-zw-timestamp": timestamp,
          "x-zw-nonce": nonce,
          "x-zw-signature": signature
        },
        body
      });
    } catch {
      throw new Error("REPLAY_STORE_UNAVAILABLE");
    }
    if (response.status === 204) return true;
    if (response.status === 409) return false;
    await response.body?.cancel().catch(() => undefined);
    throw new Error("REPLAY_STORE_UNAVAILABLE");
  };
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

// Date.now() can move backwards after a clock correction. Clamp it so
// entries inserted into a Map always have non-decreasing expiry timestamps.
function createNonDecreasingClock(now) {
  let last = -1;
  return () => {
    const value = now();
    if (!Number.isSafeInteger(value) || value < 0) throw new Error("CLOCK_INVALID");
    last = Math.max(last, value);
    return last;
  };
}

// Expirations are inserted in Map order and never extended in place. With a
// non-decreasing clock and one fixed TTL per map, expired entries form a prefix.
// Pruning therefore costs O(expired entries), not O(cache size) on every request.
function pruneExpiredPrefix(entries, currentTime, readExpiry) {
  for (const [key, value] of entries) {
    if (readExpiry(value) > currentTime) break;
    entries.delete(key);
  }
}

export function createRateLimiter(options = {}) {
  const now = options.now ?? Date.now;
  const maxBuckets = options.maxBuckets ?? MAX_RATE_BUCKETS;
  if (typeof now !== "function" || !Number.isInteger(maxBuckets) ||
      maxBuckets < 1 || maxBuckets > MAX_RATE_BUCKETS) {
    throw new Error("RATE_LIMITER_CONFIG_INVALID");
  }

  const clock = createNonDecreasingClock(now);
  const buckets = new Map();
  return ip => {
    if (typeof ip !== "string" || ip.length === 0 || ip.length > 128) return false;
    let currentTime;
    try { currentTime = clock(); } catch { return false; }

    pruneExpiredPrefix(buckets, currentTime, bucket => bucket.expiresAt);
    const current = buckets.get(ip);
    if (current) {
      current.count += 1;
      return current.count <= RATE_LIMIT;
    }

    // Keep attacker-controlled source-IP cardinality bounded. If every slot
    // still has a live window, reject new IPs rather than evicting a live limit.
    if (buckets.size >= maxBuckets) return false;
    const expiresAt = currentTime + RATE_WINDOW_MS;
    if (!Number.isSafeInteger(expiresAt)) return false;
    buckets.set(ip, { expiresAt, count: 1 });
    return true;
  };
}

export function createProbeHandler(options = {}) {
  const secret = options.secret;
  if (typeof secret !== "string" || new TextEncoder().encode(secret).byteLength < 32) {
    throw new Error("PROBE_SHARED_SECRET_REQUIRED");
  }
  const probe = options.probe ?? runProbe;
  const webhook = options.webhook ?? runWebhook;
  const claimNonce = options.claimNonce;
  if (claimNonce !== undefined && typeof claimNonce !== "function") throw new Error("REPLAY_GUARD_CONFIG_INVALID");
  const now = options.now ?? (() => Date.now());
  const nonces = new Map();
  const clock = createNonDecreasingClock(now);
  const allowRate = createRateLimiter({ now });
  let active = 0;

  return async (request, response) => {
    if (request.method === "GET" && request.url === "/healthz") {
      sendJson(response, 200, { status: "ok" });
      return;
    }
    const isProbeRoute = request.method === "POST" && request.url === "/v1/probe";
    const isWebhookRoute = request.method === "POST" && request.url === "/v1/webhook";
    if (!isProbeRoute && !isWebhookRoute) {
      sendJson(response, 404, { error: "NOT_FOUND" });
      return;
    }

    const ip = request.socket?.remoteAddress || "unknown";
    if (!allowRate(ip)) {
      sendJson(response, 429, { error: "RATE_LIMITED" });
      return;
    }
    if (active >= MAX_ACTIVE_EGRESS) {
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
      try { body = await readBody(request, isWebhookRoute ? MAX_WEBHOOK_JOB_BYTES : MAX_BODY_BYTES); }
      catch (error) {
        sendJson(response, error?.message === "BODY_TOO_LARGE" ? 413 : 400, { error: error?.message === "BODY_TOO_LARGE" ? "BODY_TOO_LARGE" : "INVALID_REQUEST" });
        return;
      }

      const timestampText = request.headers["x-zw-timestamp"];
      const nonce = request.headers["x-zw-nonce"];
      const signature = request.headers["x-zw-signature"];
      const currentTime = clock();
      const timestamp = typeof timestampText === "string" && /^\d{10}$/.test(timestampText) ? Number(timestampText) : NaN;
      const currentSeconds = Math.floor(currentTime / 1000);
      if (!Number.isSafeInteger(timestamp) || Math.abs(currentSeconds - timestamp) > MAX_CLOCK_SKEW_SECONDS ||
          typeof nonce !== "string" || !/^[A-Za-z0-9_-]{16,64}$/.test(nonce) ||
          !validSignature(secret, timestampText, nonce, body, signature)) {
        sendJson(response, 401, { error: "UNAUTHORIZED" });
        return;
      }

      if (claimNonce) {
        let claimed = false;
        try {
          claimed = await claimNonce({ timestamp: timestampText, nonce });
        } catch {
          sendJson(response, 503, { error: "REPLAY_GUARD_UNAVAILABLE" });
          return;
        }
        if (claimed !== true) {
          sendJson(response, 409, { error: "REPLAY_REJECTED" });
          return;
        }
      } else {
        // The in-memory fallback is for isolated handler tests only. The
        // standalone server always supplies the D1-backed claimer.
        pruneExpiredPrefix(nonces, currentTime, expiresAt => expiresAt);
        if (nonces.has(nonce)) {
          sendJson(response, 409, { error: "REPLAY_REJECTED" });
          return;
        }
        if (nonces.size >= MAX_NONCES) {
          sendJson(response, 503, { error: "REPLAY_GUARD_FULL" });
          return;
        }
        const nonceExpiresAt = currentTime + NONCE_TTL_MS;
        if (!Number.isSafeInteger(nonceExpiresAt)) {
          sendJson(response, 503, { error: "REPLAY_GUARD_UNAVAILABLE" });
          return;
        }
        nonces.set(nonce, nonceExpiresAt);
      }

      let job;
      try {
        const parsed = JSON.parse(body);
        job = isWebhookRoute ? normalizeWebhookInput(parsed, currentTime) : normalizeProbeInput(parsed);
      } catch {
        sendJson(response, 400, { error: isWebhookRoute ? "INVALID_WEBHOOK_JOB" : "INVALID_PROBE_JOB" });
        return;
      }

      const result = isWebhookRoute ? await webhook(job) : await probe(job);
      sendJson(response, 200, { result });
    } catch {
      if (!response.headersSent) sendJson(response, 502, { error: isWebhookRoute ? "WEBHOOK_FAILED" : "PROBE_FAILED" });
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
  if (!env.PROBE_REPLAY_URL) throw new Error("PROBE_REPLAY_URL_REQUIRED");
  const claimNonce = createDurableNonceClaimer({ url: env.PROBE_REPLAY_URL, secret: env.PROBE_SHARED_SECRET });
  const handler = createProbeHandler({ secret: env.PROBE_SHARED_SECRET, claimNonce });
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
