import { describe, expect, it } from "vitest";
import {
  createWebhookSecret,
  decryptWebhookValue,
  encryptWebhookValue,
  normalizeWebhookDestination
} from "./webhook-secrets";

const KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

describe("webhook secret encryption", () => {
  it("generates a unique 256-bit one-time secret", () => {
    const first = createWebhookSecret();
    const second = createWebhookSecret();
    expect(first).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(second).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(second).not.toBe(first);
  });

  it("round-trips encrypted values with tenant and field binding", async () => {
    const context = "zetuwatch:webhook:v1:org-1:endpoint-1:secret";
    const encrypted = await encryptWebhookValue("whsec_example-secret", KEY, context);
    expect(encrypted.ciphertext).not.toContain("whsec_example-secret");
    expect(encrypted.nonce).toMatch(/^[A-Za-z0-9_-]{16}$/);
    await expect(decryptWebhookValue(encrypted, KEY, context)).resolves.toBe("whsec_example-secret");
  });

  it("rejects ciphertext copied to another tenant, endpoint or field", async () => {
    const encrypted = await encryptWebhookValue("https://hooks.example.com/events", KEY, "org-1:endpoint-1:url");
    await expect(decryptWebhookValue(encrypted, KEY, "org-2:endpoint-1:url")).rejects.toThrow("WEBHOOK_DECRYPT_FAILED");
    await expect(decryptWebhookValue(encrypted, KEY, "org-1:endpoint-2:url")).rejects.toThrow("WEBHOOK_DECRYPT_FAILED");
    await expect(decryptWebhookValue(encrypted, KEY, "org-1:endpoint-1:secret")).rejects.toThrow("WEBHOOK_DECRYPT_FAILED");
  });

  it("rejects tampering, malformed key material and oversized values", async () => {
    const encrypted = await encryptWebhookValue("secret", KEY, "context");
    const first = encrypted.ciphertext[0] === "A" ? "B" : "A";
    const tampered = { ...encrypted, ciphertext: first + encrypted.ciphertext.slice(1) };
    await expect(decryptWebhookValue(tampered, KEY, "context")).rejects.toThrow();
    await expect(encryptWebhookValue("secret", "not-a-key", "context")).rejects.toThrow("WEBHOOK_ENCRYPTION_KEY_INVALID");
    await expect(encryptWebhookValue("x".repeat(4_097), KEY, "context")).rejects.toThrow("WEBHOOK_VALUE_INVALID");
  });
});

describe("webhook destination syntax policy", () => {
  it("normalizes a public HTTPS destination without exposing DNS as verified", () => {
    expect(normalizeWebhookDestination("https://Hooks.Example.com:443/v1/events?token=private")).toEqual({
      url: "https://hooks.example.com/v1/events?token=private",
      hostname: "hooks.example.com"
    });
  });

  it.each([
    "http://hooks.example.com/events",
    "https://user:pass@hooks.example.com/events",
    "https://hooks.example.com:8443/events",
    "https://localhost/events",
    "https://127.0.0.1/events",
    "https://2130706433/events",
    "https://[::1]/events",
    "https://service.internal/events",
    "https://service.example.test/events",
    "https://hooks.example.com/events#fragment",
    "https://hooks.example.com/events\nX-Injected: yes"
  ])("rejects unsafe or unsupported destination %s", value => {
    expect(() => normalizeWebhookDestination(value)).toThrow();
  });
});
