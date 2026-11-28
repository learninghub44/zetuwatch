import { describe, expect, it } from "vitest";
import { MAX_WEBHOOK_ATTEMPTS, webhookRetryDelaySeconds } from "./webhook-outbox";

describe("webhook delivery retry policy", () => {
  it("uses bounded exponential delays and stops after the final attempt", () => {
    expect(webhookRetryDelaySeconds(1)).toBe(30);
    expect(webhookRetryDelaySeconds(2)).toBe(120);
    expect(webhookRetryDelaySeconds(3)).toBe(600);
    expect(webhookRetryDelaySeconds(4)).toBe(1_800);
    expect(webhookRetryDelaySeconds(5)).toBe(7_200);
    expect(webhookRetryDelaySeconds(6)).toBe(21_600);
    expect(webhookRetryDelaySeconds(7)).toBe(21_600);
    expect(webhookRetryDelaySeconds(MAX_WEBHOOK_ATTEMPTS)).toBeNull();
  });

  it("honors Retry-After without exceeding the six-hour cap", () => {
    expect(webhookRetryDelaySeconds(1, 90)).toBe(90);
    expect(webhookRetryDelaySeconds(1, 99_999)).toBe(21_600);
    expect(webhookRetryDelaySeconds(2, -1)).toBe(120);
    expect(webhookRetryDelaySeconds(2, Number.NaN)).toBe(120);
  });

  it("rejects invalid attempt numbers", () => {
    for (const attempt of [0, -1, 1.5, MAX_WEBHOOK_ATTEMPTS + 1]) {
      expect(() => webhookRetryDelaySeconds(attempt)).toThrow("WEBHOOK_ATTEMPT_INVALID");
    }
  });
});
