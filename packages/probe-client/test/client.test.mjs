import test from "node:test";
import assert from "node:assert/strict";
import { signProbeRequest } from "../../../apps/probe-agent/src/server.mjs";
import { sendProbeJob, signProbePayload } from "../src/client.mjs";

const secret = "test-only-shared-secret-with-at-least-32-bytes";
const job = { targetUrl: "https://monitor.example.com/health", method: "GET", expectedStatus: 200, timeoutMs: 2_000, maxRedirects: 0 };

test("Worker-compatible HMAC matches the Node agent canonical signature", async () => {
  const timestamp = "1794912000";
  const nonce = "abcdefghijklmnopqrstuvwx";
  const body = JSON.stringify(job);
  assert.equal(await signProbePayload(secret, timestamp, nonce, body), signProbeRequest(secret, timestamp, nonce, body));
});

test("sends a signed job and validates the normalized response", async () => {
  let request;
  const result = await sendProbeJob("https://probe.example/v1/probe", secret, job, {
    now: () => 1_794_912_000_000,
    fetcher: async (url, init) => {
      request = { url, init };
      const expected = signProbeRequest(secret, init.headers["x-zw-timestamp"], init.headers["x-zw-nonce"], init.body);
      assert.equal(init.headers["x-zw-signature"], expected);
      return new Response(JSON.stringify({ result: { isUp: true, statusCode: 200, responseTimeMs: 25, errorCode: null, redirectCount: 0 } }), {
        status: 200, headers: { "content-type": "application/json" }
      });
    }
  });
  assert.equal(request.url, "https://probe.example/v1/probe");
  assert.equal(request.init.redirect, "error");
  assert.equal(result.isUp, true);
  assert.equal(result.responseTimeMs, 25);
});

test("rejects insecure agent endpoints and arbitrary request fields", async () => {
  await assert.rejects(sendProbeJob("http://probe.example/v1/probe", secret, job), /PROBE_AGENT_ENDPOINT_INVALID/);
  await assert.rejects(sendProbeJob("https://probe.example/v1/probe", secret, { ...job, headers: { authorization: "secret" } }), /PROBE_JOB_INVALID/);
});

test("supports a 30-second monitor timeout with a bounded Worker request deadline", async () => {
  const result = await sendProbeJob(
    "https://probe.example/v1/probe",
    secret,
    { ...job, timeoutMs: 30_000 },
    {
      requestTimeoutMs: 35_000,
      fetcher: async () => new Response(JSON.stringify({
        result: { isUp: true, statusCode: 200, responseTimeMs: 25, errorCode: null, redirectCount: 0 }
      }), { status: 200, headers: { "content-type": "application/json" } })
    }
  );
  assert.equal(result.isUp, true);
  await assert.rejects(sendProbeJob(
    "https://probe.example/v1/probe",
    secret,
    { ...job, timeoutMs: 30_000 },
    { requestTimeoutMs: 35_001, fetcher: async () => { throw new Error("must not fetch"); } }
  ), /PROBE_AGENT_TIMEOUT_INVALID/);
});

test("rejects oversized and malformed agent responses", async () => {
  await assert.rejects(sendProbeJob("https://probe.example/v1/probe", secret, job, {
    fetcher: async () => new Response("x".repeat(5 * 1024), { status: 200, headers: { "content-type": "application/json" } })
  }), /PROBE_AGENT_RESPONSE_TOO_LARGE/);
  await assert.rejects(sendProbeJob("https://probe.example/v1/probe", secret, job, {
    fetcher: async () => new Response(JSON.stringify({ result: { isUp: true } }), { status: 200, headers: { "content-type": "application/json" } })
  }), /PROBE_AGENT_INVALID_RESPONSE/);
});
