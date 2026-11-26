import test from "node:test";
import assert from "node:assert/strict";
import { sendWebhookJob } from "../src/webhook-client.mjs";
import { signProbePayload } from "../src/client.mjs";

const endpoint = "https://agent.zetuwatch.example.com/v1/probe";
const secret = "test-only-shared-secret-with-at-least-32-bytes";
const eventId = "6a9b0f2e-1c4d-4e7a-9b12-123456789abc";
const now = 1_800_000_000_000;
const payload = JSON.stringify({
  eventId, type: "incident.opened", createdAt: new Date(now).toISOString(), data: {}
});
const job = {
  destinationUrl: "https://hooks.customer.com/events",
  eventId,
  payload,
  signatureHeader: "t=" + String(Math.floor(now / 1000)) + ",v1=" + "a".repeat(64)
};
function response(result, status = 200, contentType = "application/json") {
  return new Response(JSON.stringify({ result }), { status, headers: { "content-type": contentType } });
}
const success = { delivered: true, responseStatus: 204, errorCode: null, retryAfterSeconds: null };

test("sends only the normalized signed webhook job to the dedicated agent route", async () => {
  let captured;
  const result = await sendWebhookJob(endpoint, secret, job, {
    now: () => now,
    fetcher: async (url, init) => {
      captured = { url, init };
      return response(success);
    }
  });
  assert.deepEqual(result, success);
  assert.equal(captured.url, "https://agent.zetuwatch.example.com/v1/webhook");
  assert.equal(captured.init.method, "POST");
  assert.equal(captured.init.redirect, "error");
  assert.equal(captured.init.credentials, "omit");
  assert.equal(captured.init.cache, "no-store");
  assert.equal(captured.init.headers["content-type"], "application/json");
  const outerSignature = await signProbePayload(
    secret,
    captured.init.headers["x-zw-timestamp"],
    captured.init.headers["x-zw-nonce"],
    captured.init.body
  );
  assert.equal(captured.init.headers["x-zw-signature"], outerSignature);
  const sent = JSON.parse(captured.init.body);
  assert.equal(sent.destinationUrl, job.destinationUrl);
  assert.equal(sent.eventId, eventId);
  assert.equal(Buffer.from(sent.payloadBase64, "base64url").toString("utf8"), payload);
  assert.equal(sent.signatureHeader, job.signatureHeader);
});

test("rejects unsafe endpoints and webhook job inputs before fetch", async () => {
  const fetcher = async () => { throw new Error("must not fetch"); };
  await assert.rejects(sendWebhookJob("http://agent.example.com/v1/probe", secret, job, { now: () => now, fetcher }), /PROBE_AGENT_ENDPOINT_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, { ...job, destinationUrl: "http://127.0.0.1/" }, { now: () => now, fetcher }), /WEBHOOK_DESTINATION_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, { ...job, eventId: "bad" }, { now: () => now, fetcher }), /WEBHOOK_EVENT_ID_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, { ...job, payload: "not-json" }, { now: () => now, fetcher }), /WEBHOOK_PAYLOAD_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, { ...job, signatureHeader: "bad" }, { now: () => now, fetcher }), /WEBHOOK_SIGNATURE_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, {
    ...job, signatureHeader: "t=" + String(Math.floor(now / 1000) - 600) + ",v1=" + "a".repeat(64)
  }, { now: () => now, fetcher }), /WEBHOOK_SIGNATURE_STALE/);
});

test("validates agent result invariants and response size", async () => {
  await assert.rejects(sendWebhookJob(endpoint, secret, job, {
    now: () => now, fetcher: async () => response({ ...success, delivered: false })
  }), /WEBHOOK_AGENT_INVALID_RESPONSE/);
  await assert.rejects(sendWebhookJob(endpoint, secret, job, {
    now: () => now, fetcher: async () => response(success, 200, "text/plain")
  }), /WEBHOOK_AGENT_INVALID_RESPONSE/);
  await assert.rejects(sendWebhookJob(endpoint, secret, job, {
    now: () => now,
    fetcher: async () => new Response("x".repeat(5 * 1024), {
      status: 200, headers: { "content-type": "application/json" }
    })
  }), /WEBHOOK_AGENT_RESPONSE_TOO_LARGE/);
});

test("rejects invalid timeout and maps unavailable agent failures", async () => {
  await assert.rejects(sendWebhookJob(endpoint, secret, job, {
    now: () => now, requestTimeoutMs: 30_000
  }), /WEBHOOK_AGENT_TIMEOUT_INVALID/);
  await assert.rejects(sendWebhookJob(endpoint, secret, job, {
    now: () => now, fetcher: async () => { throw new Error("offline"); }
  }), /WEBHOOK_AGENT_UNAVAILABLE/);
});
