import test from "node:test";
import assert from "node:assert/strict";
import { signProbePayload, verifyProbePayload } from "../src/client.mjs";

const secret = "test-only-shared-secret-with-at-least-32-bytes";
const timestamp = "1800000000";
const nonce = "0123456789abcdef0123456789abcdef";
const body = JSON.stringify({ nonce });

test("verifies the exact signed raw body", async () => {
  const signature = await signProbePayload(secret, timestamp, nonce, body);
  assert.equal(await verifyProbePayload(secret, timestamp, nonce, body, signature), true);
  assert.equal(await verifyProbePayload(secret, timestamp, nonce, body + " ", signature), false);
  assert.equal(await verifyProbePayload(secret, timestamp, nonce, body, "0".repeat(64)), false);
});

test("rejects malformed signed replay inputs", async () => {
  assert.equal(await verifyProbePayload("short", timestamp, nonce, body, "0".repeat(64)), false);
  assert.equal(await verifyProbePayload(secret, "bad", nonce, body, "0".repeat(64)), false);
  assert.equal(await verifyProbePayload(secret, timestamp, "bad", body, "0".repeat(64)), false);
  assert.equal(await verifyProbePayload(secret, timestamp, nonce, body, "bad"), false);
});
