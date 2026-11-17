import { describe, expect, it } from "vitest";
import {
  createWebhookSecret,
  MAX_WEBHOOK_PAYLOAD_BYTES,
  signWebhookPayload,
  verifyWebhookSignature
} from "../packages/notifications-core/src/webhook-signing";
import {
  isRetryableWebhookStatus,
  MAX_WEBHOOK_DELIVERY_ATTEMPTS,
  nextWebhookAttemptAt,
  WEBHOOK_RETRY_MAX_DELAY_MS,
  webhookRetryDelayMs
} from "../packages/notifications-core/src/retry-policy";

describe("Webhook signing", () => {
  it("creates independent 256-bit prefixed secrets", () => {
    const first = createWebhookSecret();
    const second = createWebhookSecret();
    expect(first).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(second).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(second).not.toBe(first);
  });

  it("signs and verifies the exact request body", async () => {
    const secret = createWebhookSecret();
    const body = JSON.stringify({ id: "evt_123", type: "incident.opened" });
    const header = await signWebhookPayload(secret, body, 1_800_000_000);

    expect(header).toMatch(/^t=1800000000,v1=[a-f0-9]{64}$/);
    await expect(verifyWebhookSignature(secret, body, header, 1_800_000_000)).resolves.toBe(true);
    await expect(verifyWebhookSignature(secret, body + " ", header, 1_800_000_000)).resolves.toBe(false);
  });

  it("rejects stale and future-dated signatures", async () => {
    const secret = createWebhookSecret();
    const body = "{\"id\":\"evt_123\"}";
    const stale = await signWebhookPayload(secret, body, 1_000);
    const future = await signWebhookPayload(secret, body, 2_000);

    await expect(verifyWebhookSignature(secret, body, stale, 1_400)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, body, future, 1_600)).resolves.toBe(false);
  });

  it("rejects malformed, duplicate and tampered signature headers", async () => {
    const secret = createWebhookSecret();
    const body = "{\"ok\":true}";
    const valid = await signWebhookPayload(secret, body, 1_800_000_000);
    const originalSignature = valid.slice(valid.indexOf("v1=") + 3);
    const tamperedLastHex = originalSignature.endsWith("0") ? "1" : "0";
    const tampered = valid.slice(0, -1) + tamperedLastHex;

    await expect(verifyWebhookSignature(secret, body, "t=1,v1=abc", 1_800_000_000)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, body, valid + ",v1=" + "0".repeat(64), 1_800_000_000)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, body, tampered, 1_800_000_000)).resolves.toBe(false);
    await expect(verifyWebhookSignature("wrong-secret", body, valid, 1_800_000_000)).resolves.toBe(false);
  });

  it("fails closed for oversized payloads and invalid signing inputs", async () => {
    const secret = createWebhookSecret();
    const oversized = "x".repeat(MAX_WEBHOOK_PAYLOAD_BYTES + 1);

    await expect(signWebhookPayload(secret, oversized, 1_800_000_000)).rejects.toThrow("WEBHOOK_PAYLOAD_TOO_LARGE");
    await expect(signWebhookPayload("short", "body", 1_800_000_000)).rejects.toThrow("WEBHOOK_SECRET_INVALID");
    await expect(signWebhookPayload(secret, "body", -1)).rejects.toThrow("WEBHOOK_TIMESTAMP_INVALID");
    await expect(verifyWebhookSignature(secret, oversized, "invalid", 1_800_000_000)).resolves.toBe(false);
  });
});

describe("Webhook retry policy", () => {
  it("retries network failures and transient HTTP statuses only", () => {
    expect(isRetryableWebhookStatus(null)).toBe(true);
    expect(isRetryableWebhookStatus(408)).toBe(true);
    expect(isRetryableWebhookStatus(425)).toBe(true);
    expect(isRetryableWebhookStatus(429)).toBe(true);
    expect(isRetryableWebhookStatus(503)).toBe(true);
    expect(isRetryableWebhookStatus(204)).toBe(false);
    expect(isRetryableWebhookStatus(302)).toBe(false);
    expect(isRetryableWebhookStatus(400)).toBe(false);
    expect(isRetryableWebhookStatus(401)).toBe(false);
    expect(isRetryableWebhookStatus(600)).toBe(false);
  });

  it("uses exponential backoff with bounded jitter", () => {
    expect(webhookRetryDelayMs(1, 0)).toBe(15_000);
    expect(webhookRetryDelayMs(1, 1)).toBe(45_000);
    expect(webhookRetryDelayMs(2, 0.5)).toBe(60_000);
    expect(webhookRetryDelayMs(MAX_WEBHOOK_DELIVERY_ATTEMPTS - 1, 1))
      .toBeLessThanOrEqual(WEBHOOK_RETRY_MAX_DELAY_MS);
  });

  it("returns ISO retry times and stops after the configured attempt budget", () => {
    const now = Date.UTC(2026, 10, 17, 6, 0, 0);
    expect(nextWebhookAttemptAt(1, now, 0.5)).toBe(new Date(now + 30_000).toISOString());
    expect(nextWebhookAttemptAt(MAX_WEBHOOK_DELIVERY_ATTEMPTS, now, 0.5)).toBeNull();
  });

  it("rejects invalid attempts, jitter and clocks", () => {
    expect(() => webhookRetryDelayMs(0)).toThrow("WEBHOOK_ATTEMPT_INVALID");
    expect(() => webhookRetryDelayMs(1, 1.1)).toThrow("WEBHOOK_JITTER_INVALID");
    expect(() => nextWebhookAttemptAt(1, Number.NaN)).toThrow("WEBHOOK_CLOCK_INVALID");
  });
});
