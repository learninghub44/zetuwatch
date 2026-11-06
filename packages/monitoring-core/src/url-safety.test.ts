import { describe, expect, it } from "vitest";
import { validateMonitorUrl } from "./url-safety";

describe("validateMonitorUrl", () => {
  it("accepts ordinary public HTTP and HTTPS URLs", () => {
    expect(validateMonitorUrl("https://example.com/health").hostname).toBe("example.com");
    expect(validateMonitorUrl("http://example.com").protocol).toBe("http:");
  });

  it("rejects malformed URLs and unsupported protocols", () => {
    expect(() => validateMonitorUrl("not a URL")).toThrow("INVALID_URL");
    expect(() => validateMonitorUrl("ftp://example.com/file")).toThrow("UNSUPPORTED_PROTOCOL");
  });

  it("rejects embedded credentials and unexpected ports", () => {
    expect(() => validateMonitorUrl("https://user:pass@example.com")).toThrow("URL_CREDENTIALS_NOT_ALLOWED");
    expect(() => validateMonitorUrl("https://example.com:8443")).toThrow("PORT_NOT_ALLOWED");
  });

  it("rejects local hostnames", () => {
    expect(() => validateMonitorUrl("http://localhost")).toThrow("HOST_NOT_ALLOWED");
    expect(() => validateMonitorUrl("http://printer.local")).toThrow("HOST_NOT_ALLOWED");
    expect(() => validateMonitorUrl("http://service.localhost")).toThrow("HOST_NOT_ALLOWED");
  });

  it("rejects common private and link-local IPv4 destinations", () => {
    for (const address of [
      "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1",
      "169.254.169.254", "172.16.0.1", "192.168.1.1", "198.18.0.1", "224.0.0.1"
    ]) {
      expect(() => validateMonitorUrl(`http://${address}`)).toThrow();
    }
  });

  it("rejects common private IPv6 destinations", () => {
    for (const address of ["::1", "fc00::1", "fd00::1", "fe80::1"]) {
      expect(() => validateMonitorUrl(`http://[${address}]`)).toThrow();
    }
  });

  it("rejects excessively long URLs", () => {
    expect(() => validateMonitorUrl("https://example.com/" + "a".repeat(2048))).toThrow("URL_TOO_LONG");
  });
});
