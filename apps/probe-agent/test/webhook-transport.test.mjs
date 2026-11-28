import test from "node:test";
import assert from "node:assert/strict";
import {
  buildPinnedWebhookRequestOptions,
  parseRetryAfter,
  MAX_WEBHOOK_RESPONSE_BYTES
} from "../src/webhook-transport.mjs";

const url = new URL("https://hooks.customer.com/path?key=opaque");
const body = Buffer.from('{"eventId":"6a9b0f2e-1c4d-4e7a-9b12-123456789abc"}');
const eventId = "6a9b0f2e-1c4d-4e7a-9b12-123456789abc";
const signatureHeader = "t=1800000000,v1=" + "b".repeat(64);

test("pins the socket address while preserving original hostname, SNI and TLS verification", () => {
  const options = buildPinnedWebhookRequestOptions(url, "93.184.216.34", { body, eventId, signatureHeader });
  assert.equal(options.protocol, "https:");
  assert.equal(options.hostname, "hooks.customer.com");
  assert.equal(options.servername, "hooks.customer.com");
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.agent, false);
  assert.equal(options.method, "POST");
  assert.equal(options.path, "/path?key=opaque");
  assert.equal(options.headers["content-length"], String(body.length));
  assert.equal(options.headers["x-zetuwatch-event-id"], eventId);
  assert.equal(options.headers["x-zetuwatch-signature"], signatureHeader);
  let pinned;
  options.lookup("ignored.invalid", {}, (_error, address, family) => { pinned = { address, family }; });
  assert.deepEqual(pinned, { address: "93.184.216.34", family: 4 });
  let familyError;
  options.lookup("ignored.invalid", { family: 6 }, error => { familyError = error; });
  assert.match(familyError.message, /PINNED_ADDRESS_FAMILY_MISMATCH/);
});

test("rejects non-public pinned addresses, IP literals and non-HTTPS destinations", () => {
  assert.throws(() => buildPinnedWebhookRequestOptions(url, "127.0.0.1", {
    body, eventId, signatureHeader
  }), /PINNED_ADDRESS_NOT_PUBLIC/);
  assert.throws(() => buildPinnedWebhookRequestOptions(new URL("https://127.0.0.1/"), "93.184.216.34", {
    body, eventId, signatureHeader
  }), /WEBHOOK_HOST_INVALID/);
  assert.throws(() => buildPinnedWebhookRequestOptions(new URL("http://hooks.customer.com/"), "93.184.216.34", {
    body, eventId, signatureHeader
  }), /WEBHOOK_DESTINATION_INVALID/);
  assert.throws(() => buildPinnedWebhookRequestOptions(new URL("https://user:pass@hooks.customer.com/"), "93.184.216.34", {
    body, eventId, signatureHeader
  }), /WEBHOOK_DESTINATION_INVALID/);
  assert.throws(() => buildPinnedWebhookRequestOptions(new URL("https://hooks.customer.com/#fragment"), "93.184.216.34", {
    body, eventId, signatureHeader
  }), /WEBHOOK_DESTINATION_INVALID/);
});

test("rejects invalid body sizes and header injection", () => {
  assert.throws(() => buildPinnedWebhookRequestOptions(url, "93.184.216.34", {
    body: Buffer.alloc(256 * 1024 + 1), eventId, signatureHeader
  }), /WEBHOOK_PAYLOAD_INVALID/);
  assert.throws(() => buildPinnedWebhookRequestOptions(url, "93.184.216.34", {
    body, eventId: "x\r\nInjected: yes", signatureHeader
  }), /WEBHOOK_HEADERS_INVALID/);
  assert.throws(() => buildPinnedWebhookRequestOptions(url, "93.184.216.34", {
    body, eventId, signatureHeader: "x\r\nInjected: yes"
  }), /WEBHOOK_HEADERS_INVALID/);
});

test("parses bounded Retry-After seconds and HTTP dates", () => {
  const now = Date.parse("2026-11-26T06:00:00.000Z");
  assert.equal(parseRetryAfter("90", now), 90);
  assert.equal(parseRetryAfter("99999999", now), 21_600);
  assert.equal(parseRetryAfter(new Date(now + 30_000).toUTCString(), now), 30);
  assert.equal(parseRetryAfter("not-a-date", now), null);
  assert.equal(parseRetryAfter("-1", now), null);
  assert.equal(MAX_WEBHOOK_RESPONSE_BYTES, 8 * 1024);
});
