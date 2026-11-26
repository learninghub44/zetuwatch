import test from "node:test";
import assert from "node:assert/strict";
import { normalizeWebhookInput, runWebhook } from "../src/webhook-runner.mjs";

const publicAddress = "93.184.216.34";
const now = 1_800_000_000_000;
const eventId = "6a9b0f2e-1c4d-4e7a-9b12-123456789abc";
function rawJob(overrides = {}) {
  const payload = JSON.stringify({
    eventId,
    type: "incident.opened",
    createdAt: new Date(now).toISOString(),
    data: { incident: { id: "incident-1", status: "investigating" } }
  });
  const timestamp = String(Math.floor(now / 1000));
  return {
    destinationUrl: "https://hooks.customer.com/events?source=zetuwatch",
    eventId,
    payloadBase64: Buffer.from(payload).toString("base64url"),
    signatureHeader: "t=" + timestamp + ",v1=" + "a".repeat(64),
    ...overrides
  };
}
function normalized(overrides = {}) { return normalizeWebhookInput(rawJob(overrides), now); }

test("normalizes a bounded signed HTTPS webhook job without changing payload bytes", () => {
  const raw = rawJob();
  const expected = Buffer.from(raw.payloadBase64, "base64url");
  const job = normalizeWebhookInput(raw, now);
  assert.equal(job.destinationUrl, raw.destinationUrl);
  assert.equal(job.eventId, eventId);
  assert.deepEqual(job.body, expected);
  assert.equal(job.signatureHeader, raw.signatureHeader);
});

test("rejects non-HTTPS, IP-literal, credentialed, fragmented and non-default-port destinations", () => {
  for (const destinationUrl of [
    "http://hooks.customer.com/events",
    "https://127.0.0.1/events",
    "https://2130706433/events",
    "https://user:pass@hooks.customer.com/events",
    "https://hooks.customer.com:8443/events",
    "https://hooks.customer.com/events#fragment",
    "https://localhost/events",
    "https://hooks.customer.com.test/events",
    "https://hooks.customer.home/events",
    "https://hooks.customer.onion/events",
    "https://metadata.google.internal/events"
  ]) {
    assert.throws(() => normalizeWebhookInput(rawJob({ destinationUrl }), now), /WEBHOOK_DESTINATION_INVALID/);
  }
});

test("rejects invalid event IDs, signatures, stale timestamps and event/body mismatches", () => {
  assert.throws(() => normalizeWebhookInput(rawJob({ eventId: "bad" }), now), /WEBHOOK_EVENT_ID_INVALID/);
  assert.throws(() => normalizeWebhookInput(rawJob({ signatureHeader: "v1=bad" }), now), /WEBHOOK_SIGNATURE_INVALID/);
  assert.throws(() => normalizeWebhookInput(rawJob({
    signatureHeader: "t=" + (Math.floor(now / 1000) - 600) + ",v1=" + "a".repeat(64)
  }), now), /WEBHOOK_SIGNATURE_STALE/);
  const mismatch = JSON.stringify({ eventId: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", type: "incident.opened" });
  assert.throws(() => normalizeWebhookInput(rawJob({
    payloadBase64: Buffer.from(mismatch).toString("base64url")
  }), now), /WEBHOOK_PAYLOAD_INVALID/);
});

test("rejects malformed, non-canonical and oversized payload encodings", () => {
  assert.throws(() => normalizeWebhookInput(rawJob({ payloadBase64: "%%%" }), now), /WEBHOOK_PAYLOAD_INVALID/);
  assert.throws(() => normalizeWebhookInput(rawJob({ payloadBase64: "YQ=" }), now), /WEBHOOK_PAYLOAD_INVALID/);
  assert.throws(() => normalizeWebhookInput(rawJob({
    payloadBase64: Buffer.from("x".repeat(256 * 1024 + 1)).toString("base64url")
  }), now), /WEBHOOK_PAYLOAD_INVALID/);
});

test("resolves all records and pins the selected public address for one HTTPS request", async () => {
  const job = normalized();
  const resolved = [];
  const requests = [];
  const result = await runWebhook(job, {
    now: () => now,
    resolver: async (hostname, timeoutMs) => {
      resolved.push({ hostname, timeoutMs });
      return [publicAddress, "2606:4700:4700::1111"];
    },
    requester: async (url, address, options) => {
      requests.push({ hostname: url.hostname, address, options });
      return { statusCode: 204, retryAfterSeconds: null };
    }
  });
  assert.deepEqual(resolved, [{ hostname: "hooks.customer.com", timeoutMs: 2_500 }]);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].address, publicAddress);
  assert.equal(requests[0].hostname, "hooks.customer.com");
  assert.deepEqual(requests[0].options.body, job.body);
  assert.equal(result.delivered, true);
  assert.equal(result.responseStatus, 204);
});

test("rejects a mixed public/private DNS answer set before opening a socket", async () => {
  let requests = 0;
  const result = await runWebhook(normalized(), {
    now: () => now,
    resolver: async () => [publicAddress, "169.254.169.254"],
    requester: async () => { requests += 1; return { statusCode: 204 }; }
  });
  assert.equal(result.delivered, false);
  assert.equal(result.errorCode, "TARGET_NOT_ALLOWED");
  assert.equal(requests, 0);
});

test("does not follow a redirect and reports it as a permanent delivery failure", async () => {
  let requests = 0;
  const result = await runWebhook(normalized(), {
    now: () => now,
    resolver: async () => [publicAddress],
    requester: async () => { requests += 1; return { statusCode: 302, location: "https://internal.example/" }; }
  });
  assert.equal(requests, 1);
  assert.deepEqual(result, {
    delivered: false, responseStatus: 302, errorCode: "REDIRECT_BLOCKED", retryAfterSeconds: null
  });
});

test("classifies receiver throttling and server errors for bounded retry policy", async () => {
  const run = async statusCode => runWebhook(normalized(), {
    now: () => now,
    resolver: async () => [publicAddress],
    requester: async () => ({ statusCode, retryAfterSeconds: 90 })
  });
  assert.deepEqual(await run(429), {
    delivered: false, responseStatus: 429, errorCode: "REMOTE_RATE_LIMITED", retryAfterSeconds: 90
  });
  assert.deepEqual(await run(503), {
    delivered: false, responseStatus: 503, errorCode: "REMOTE_SERVER_ERROR", retryAfterSeconds: 90
  });
  assert.deepEqual(await run(400), {
    delivered: false, responseStatus: 400, errorCode: "REMOTE_REJECTED", retryAfterSeconds: null
  });
});

test("recomputes the total deadline after DNS and skips a request when the budget is spent", async () => {
  let elapsed = 0;
  let requests = 0;
  const result = await runWebhook(normalized(), {
    now: () => now + elapsed,
    resolver: async () => { elapsed = 14_950; return [publicAddress]; },
    requester: async () => { requests += 1; return { statusCode: 204 }; }
  });
  assert.equal(result.errorCode, "TIMEOUT");
  assert.equal(requests, 0);
});

test("maps DNS, TLS and timeout failures to bounded error codes", async () => {
  const job = normalized();
  const dns = await runWebhook(job, {
    now: () => now, resolver: async () => { throw new Error("DNS_LOOKUP_FAILED"); }
  });
  const tls = await runWebhook(job, {
    now: () => now, resolver: async () => [publicAddress],
    requester: async () => {
      const error = new Error("certificate verify failed");
      error.code = "ERR_TLS_CERT_ALTNAME_INVALID";
      throw error;
    }
  });
  const timeout = await runWebhook(job, {
    now: () => now, resolver: async () => [publicAddress],
    requester: async () => { throw new Error("WEBHOOK_TIMEOUT"); }
  });
  assert.equal(dns.errorCode, "DNS_FAILURE");
  assert.equal(tls.errorCode, "TLS_ERROR");
  assert.equal(timeout.errorCode, "TIMEOUT");
});
