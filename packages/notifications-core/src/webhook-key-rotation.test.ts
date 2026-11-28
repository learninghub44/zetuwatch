import { describe, expect, it } from "vitest";
import { webhookRotationRetryDelayMs } from "./webhook-key-rotation";

describe("webhook master-key rotation retry policy", () => {
  it("starts with a one-hour retry after a failed row", () => {
    expect(webhookRotationRetryDelayMs(1)).toBe(60 * 60 * 1_000);
  });

  it("doubles the retry delay without exceeding one day", () => {
    expect(webhookRotationRetryDelayMs(2)).toBe(2 * 60 * 60 * 1_000);
    expect(webhookRotationRetryDelayMs(3)).toBe(4 * 60 * 60 * 1_000);
    expect(webhookRotationRetryDelayMs(5)).toBe(16 * 60 * 60 * 1_000);
    expect(webhookRotationRetryDelayMs(6)).toBe(24 * 60 * 60 * 1_000);
    expect(webhookRotationRetryDelayMs(20)).toBe(24 * 60 * 60 * 1_000);
  });

  it("rejects invalid attempt numbers rather than producing an unbounded delay", () => {
    for (const value of [0, -1, 1.5, 21, Number.NaN, Number.POSITIVE_INFINITY]) {
      expect(() => webhookRotationRetryDelayMs(value)).toThrow("WEBHOOK_KEY_ROTATION_ATTEMPT_INVALID");
    }
  });
});
