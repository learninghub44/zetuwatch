import { describe, expect, it } from "vitest";
import { createWebhookSecret } from "./webhook-secrets";
import {
  DEFAULT_WEBHOOK_TOLERANCE_SECONDS,
  MAX_WEBHOOK_PAYLOAD_BYTES,
  signWebhookPayload,
  verifyWebhookSignature
} from "./webhook-signing";

describe("timestamped webhook HMAC signatures", () => {
  it("signs and verifies the exact raw payload", async () => {
    const secret = createWebhookSecret();
    const payload = '{"event":"incident.opened","data":{"id":"evt_123"}}';
    const signature = await signWebhookPayload(secret, payload, 1_800_000_000);
    expect(signature).toMatch(/^t=1800000000,v1=[a-f0-9]{64}$/);
    await expect(verifyWebhookSignature(secret, payload, signature, 1_800_000_000)).resolves.toBe(true);
    await expect(verifyWebhookSignature(secret, payload + " ", signature, 1_800_000_000)).resolves.toBe(false);
  });

  it("rejects wrong secrets, malformed signatures and stale or future timestamps", async () => {
    const secret = createWebhookSecret();
    const wrongSecret = createWebhookSecret();
    const payload = '{"event":"incident.resolved"}';
    const signature = await signWebhookPayload(secret, payload, 1_800_000_000);
    await expect(verifyWebhookSignature(wrongSecret, payload, signature, 1_800_000_000)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, payload, "t=1800000000,v1=xyz", 1_800_000_000)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, payload, signature, 1_800_000_000 + DEFAULT_WEBHOOK_TOLERANCE_SECONDS + 1)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, payload, signature, 1_800_000_000 - DEFAULT_WEBHOOK_TOLERANCE_SECONDS - 1)).resolves.toBe(false);
  });

  it("enforces payload, timestamp and tolerance bounds", async () => {
    const secret = createWebhookSecret();
    await expect(signWebhookPayload(secret, "x".repeat(MAX_WEBHOOK_PAYLOAD_BYTES + 1), 1_800_000_000))
      .rejects.toThrow("WEBHOOK_PAYLOAD_TOO_LARGE");
    await expect(signWebhookPayload(secret, "{}", -1)).rejects.toThrow("WEBHOOK_TIMESTAMP_INVALID");
    await expect(signWebhookPayload("not-a-secret", "{}", 1_800_000_000)).rejects.toThrow("WEBHOOK_SECRET_INVALID");
    const signature = await signWebhookPayload(secret, "{}", 1_800_000_000);
    await expect(verifyWebhookSignature(secret, "{}", signature, 1_800_000_000, 29)).resolves.toBe(false);
    await expect(verifyWebhookSignature(secret, "{}", signature, 1_800_000_000, 901)).resolves.toBe(false);
  });
});
