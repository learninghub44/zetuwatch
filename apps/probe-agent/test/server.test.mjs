import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createProbeHandler, createRateLimiter, signProbeRequest } from "../src/server.mjs";

const secret = "test-only-shared-secret-with-at-least-32-bytes";
const job = { targetUrl: "https://monitor.example.com/health", method: "GET", expectedStatus: 200, timeoutMs: 2_000, maxRedirects: 0 };
function listen(server) { return new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(server.address().port))); }
function close(server) { return new Promise(resolve => server.close(resolve)); }

async function send(port, options = {}) {
  const body = options.body ?? JSON.stringify(job);
  const timestamp = options.timestamp ?? String(Math.floor(Date.now() / 1000));
  const nonce = options.nonce ?? "0123456789abcdef0123456789abcdef";
  const signature = options.signature ?? signProbeRequest(secret, timestamp, nonce, body);
  return fetch(`http://127.0.0.1:${port}${options.path ?? "/v1/probe"}`, {
    method: options.method ?? "POST",
    headers: {
      "content-type": options.contentType ?? "application/json",
      ...(options.contentEncoding ? { "content-encoding": options.contentEncoding } : {}),
      "x-zw-timestamp": timestamp,
      "x-zw-nonce": nonce,
      "x-zw-signature": signature
    },
    body: options.method === "GET" ? undefined : body
  });
}

test("requires a sufficiently strong shared secret", () => {
  assert.throws(() => createProbeHandler({ secret: "short" }), /PROBE_SHARED_SECRET_REQUIRED/);
});

test("bounds source-IP rate-limit state and fails closed until expired buckets can be reclaimed", () => {
  let currentTime = 1_000;
  const allow = createRateLimiter({ now: () => currentTime, maxBuckets: 2 });

  assert.equal(allow("198.51.100.10"), true);
  assert.equal(allow("198.51.100.11"), true);
  assert.equal(allow("198.51.100.12"), false);
  // Existing live buckets retain their own rate-limit state.
  assert.equal(allow("198.51.100.10"), true);

  currentTime += 60_000;
  // Expired buckets are reclaimed before a new source IP is admitted.
  assert.equal(allow("198.51.100.12"), true);
  assert.throws(() => createRateLimiter({ maxBuckets: 0 }), /RATE_LIMITER_CONFIG_INVALID/);
});

test("keeps rate-limit expiry order stable when the wall clock moves backwards", () => {
  let currentTime = 1_000;
  const allow = createRateLimiter({ now: () => currentTime, maxBuckets: 2 });

  assert.equal(allow("198.51.100.20"), true);
  currentTime = 0;
  assert.equal(allow("198.51.100.21"), true);

  // The clock is clamped to the last observed value, so neither live bucket
  // expires early and a full cache continues to fail closed.
  currentTime = 60_000;
  assert.equal(allow("198.51.100.22"), false);
  currentTime = 61_000;
  assert.equal(allow("198.51.100.22"), true);
});

test("fails closed when the rate-limit clock returns an invalid value", () => {
  const allow = createRateLimiter({ now: () => Number.NaN, maxBuckets: 2 });
  assert.equal(allow("198.51.100.30"), false);
});

test("prunes expired replay nonces in insertion order after a clock rollback", async () => {
  const initialTime = 1_700_000_000_000;
  let currentTime = initialTime;
  const handler = createProbeHandler({
    secret,
    now: () => currentTime,
    probe: async () => ({ isUp: true, statusCode: 200, responseTimeMs: 1, errorCode: null, redirectCount: 0 })
  });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const nonceA = "nonce-clock-a-0123456789012345";
    const nonceB = "nonce-clock-b-0123456789012345";
    assert.equal((await send(port, { nonce: nonceA, timestamp: String(initialTime / 1000) })).status, 200);

    currentTime = initialTime - 60_000;
    // A timestamp at the edge of the accepted skew is valid, but its cache
    // expiry is based on the non-decreasing clock, not the rolled-back clock.
    assert.equal((await send(port, { nonce: nonceB, timestamp: String(currentTime / 1000) })).status, 200);

    currentTime = initialTime + 240_000;
    assert.equal((await send(port, { nonce: nonceA, timestamp: String(currentTime / 1000) })).status, 409);

    currentTime = initialTime + 300_000;
    assert.equal((await send(port, { nonce: nonceA, timestamp: String(currentTime / 1000) })).status, 200);
  } finally { await close(server); }
});

test("accepts a signed bounded job and returns only the normalized result", async () => {
  let called = 0;
  const handler = createProbeHandler({ secret, probe: async received => {
    called += 1;
    assert.deepEqual(received, job);
    return { isUp: true, statusCode: 200, responseTimeMs: 12, errorCode: null, redirectCount: 0 };
  } });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const response = await send(port);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { result: { isUp: true, statusCode: 200, responseTimeMs: 12, errorCode: null, redirectCount: 0 } });
    assert.equal(called, 1);
  } finally { await close(server); }
});

test("rejects replayed nonces and tampered bodies", async () => {
  const handler = createProbeHandler({ secret, probe: async () => ({ isUp: true, statusCode: 200, responseTimeMs: 1, errorCode: null, redirectCount: 0 }) });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const nonce = "abcdef0123456789abcdef0123456789";
    assert.equal((await send(port, { nonce })).status, 200);
    assert.equal((await send(port, { nonce })).status, 409);
    const body = JSON.stringify(job);
    const valid = signProbeRequest(secret, String(Math.floor(Date.now() / 1000)), "fedcba9876543210fedcba9876543210", body);
    assert.equal((await send(port, { body: body + " ", nonce: "fedcba9876543210fedcba9876543210", signature: valid })).status, 401);
  } finally { await close(server); }
});

test("rejects stale timestamps, invalid jobs, and oversized bodies", async () => {
  const handler = createProbeHandler({ secret, probe: async () => { throw new Error("must not run"); } });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const stale = String(Math.floor(Date.now() / 1000) - 600);
    assert.equal((await send(port, { timestamp: stale })).status, 401);
    assert.equal((await send(port, { body: JSON.stringify({ ...job, headers: { authorization: "x" } }), nonce: "1123456789abcdef1123456789abcdef" })).status, 400);
    assert.equal((await send(port, { body: "x".repeat(17 * 1024), nonce: "2123456789abcdef2123456789abcdef" })).status, 413);
  } finally { await close(server); }
});

test("exposes a minimal health response without revealing configuration", async () => {
  const handler = createProbeHandler({ secret });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const response = await send(port, { method: "GET", path: "/healthz" });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
  } finally { await close(server); }
});


test("rejects non-JSON and compressed request bodies", async () => {
  const handler = createProbeHandler({ secret, probe: async () => { throw new Error("must not run"); } });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    assert.equal((await send(port, { contentType: "text/plain", nonce: "3123456789abcdef3123456789abcdef" })).status, 415);
    assert.equal((await send(port, { contentEncoding: "gzip", nonce: "4123456789abcdef4123456789abcdef" })).status, 415);
  } finally { await close(server); }
});

test("bounds concurrent probe execution", async () => {
  let started = 0;
  let signalStarted;
  const allStarted = new Promise(resolve => { signalStarted = resolve; });
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  const handler = createProbeHandler({ secret, probe: async () => {
    started += 1;
    if (started === 20) signalStarted();
    await gate;
    return { isUp: true, statusCode: 200, responseTimeMs: 1, errorCode: null, redirectCount: 0 };
  } });
  const server = createServer((request, response) => { void handler(request, response); });
  const port = await listen(server);
  try {
    const pending = Array.from({ length: 20 }, (_, index) => send(port, { nonce: ("concurrency-" + index).padEnd(32, "x") }));
    await allStarted;
    const overflow = await send(port, { nonce: "concurrency-overflow-nonce-0000" });
    assert.equal(overflow.status, 429);
    release();
    const responses = await Promise.all(pending);
    assert.equal(responses.every(response => response.status === 200), true);
  } finally {
    release?.();
    await close(server);
  }
});
