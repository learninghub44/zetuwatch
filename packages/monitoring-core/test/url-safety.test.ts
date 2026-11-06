import { describe, expect, it } from "vitest";
import { validateMonitorUrl } from "../src/url-safety";

describe("validateMonitorUrl", () => {
  it("accepts ordinary public HTTP and HTTPS endpoints", () => {
    expect(validateMonitorUrl("https://status.example.com/health").hostname)
      .toBe("status.example.com");
    expect(validateMonitorUrl("http://8.8.8.8/health").hostname).toBe("8.8.8.8");
  });

  it.each([
    "file:///etc/passwd",
    "ftp://example.com",
    "http://user:pass@example.com",
    "http://localhost",
    "http://localhost.",
    "http://service.localhost",
    "http://metadata.google.internal",
    "http://127.0.0.1",
    "http://127.1",
    "http://10.0.0.8",
    "http://100.64.0.1",
    "http://169.254.169.254",
    "http://172.16.0.1",
    "http://192.168.1.1",
    "http://192.0.2.10",
    "http://198.18.0.1",
    "http://203.0.113.8",
    "http://224.0.0.1",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://host.internal",
    "http://singlelabel"
  ])("rejects unsafe or unsupported target %s", (target) => {
    expect(() => validateMonitorUrl(target)).toThrow();
  });

  it("rejects non-standard ports", () => {
    expect(() => validateMonitorUrl("https://example.com:8443")).toThrow("PORT_NOT_ALLOWED");
  });

  it("rejects URLs longer than the supported bound", () => {
    expect(() => validateMonitorUrl("https://example.com/" + "a".repeat(2050)))
      .toThrow("URL_TOO_LONG");
  });

  it("rejects malformed input", () => {
    expect(() => validateMonitorUrl("not a URL")).toThrow("INVALID_URL");
  });
});
