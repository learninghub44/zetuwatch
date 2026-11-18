import { describe, expect, it } from "vitest";
import { notificationRetryDelaySeconds, parseRetryAfter } from "./outbox";

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
    expect(parseRetryAfter("Thu, 01 Jan 1970 00:02:00 GMT", 0)).toBe(120);
  });
});
