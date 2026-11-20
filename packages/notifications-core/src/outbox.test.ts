import { describe, expect, it } from "vitest";
import { claimDueNotificationDeliveries, notificationRetryDelaySeconds, parseRetryAfter } from "./outbox";

describe("notification retry policy", () => {
  it("uses bounded exponential backoff and stops after the sixth attempt", () => {
    expect([1, 2, 3, 4, 5, 6].map(count => notificationRetryDelaySeconds(count)))
      .toEqual([30, 120, 600, 3600, 21600, null]);
  });

  it("honors a longer provider Retry-After hint without exceeding six hours", () => {
    expect(notificationRetryDelaySeconds(1, 90)).toBe(90);
    expect(notificationRetryDelaySeconds(2, 30)).toBe(120);
    expect(notificationRetryDelaySeconds(3, 999999)).toBe(21600);
  });

  it("parses delta seconds and HTTP dates safely", () => {
    expect(parseRetryAfter("60", 0)).toBe(60);
    expect(parseRetryAfter("invalid", 0)).toBeNull();
    expect(parseRetryAfter("-1", 0)).toBeNull();
    expect(parseRetryAfter("999999", 0)).toBe(21600);
    expect(parseRetryAfter("Thu, 01 Jan 1970 00:02:00 GMT", 0)).toBe(120);
  });
});


describe("notification outbox input validation", () => {
  it("accepts ISO timestamps before validating lease tokens", async () => {
    const unusedDb = {} as D1Database;
    await expect(claimDueNotificationDeliveries(unusedDb, {
      now: "2026-11-18T09:00:00.000Z",
      token: "invalid token with whitespace"
    })).rejects.toThrow("NOTIFICATION_TOKEN_INVALID");
  });

  it("rejects timestamps without an explicit timezone", async () => {
    const unusedDb = {} as D1Database;
    await expect(claimDueNotificationDeliveries(unusedDb, {
      now: "2026-11-18 09:00:00",
      token: "notification-lease-token-0001"
    })).rejects.toThrow("NOTIFICATION_NOW_INVALID");
  });
});
