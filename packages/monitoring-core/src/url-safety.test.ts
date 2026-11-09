import { describe, expect, it } from "vitest";
import { validateMonitorUrl } from "./url-safety";

describe("validateMonitorUrl", () => {
  it("accepts ordinary public HTTP and HTTPS URLs", () => {
    expect(validateMonitorUrl("https://example.com/health").hostname).toBe("example.com");
    expect(validateMonitorUrl("http://example.com").protocol).toBe("http:");
    expect(validateMonitorUrl("https://8.8.8.8/health").hostname).toBe("8.8.8.8");
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

  it("rejects private, link-local and special-purpose IPv4 destinations", () => {
    for (const address of [
      "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1",
      "169.254.169.254", "172.16.0.1", "192.0.0.9", "192.0.2.1",
      "192.168.1.1", "198.18.0.1", "198.51.100.1", "203.0.113.1",
      "224.0.0.1", "240.0.0.1", "255.255.255.255"
    ]) {
      expect(() => validateMonitorUrl("http://" + address), address).toThrow("IP_NOT_ALLOWED");
    }
  });

  it("rejects unusual numeric IPv4 spellings after URL normalization", () => {
    for (const address of ["127.1", "2130706433", "0177.0.0.1", "0x7f000001"]) {
      expect(() => validateMonitorUrl("http://" + address), address).toThrow("IP_NOT_ALLOWED");
    }
  });

  it("rejects IPv6 literals until pinned IPv6 transport is implemented", () => {
    for (const address of ["::1", "fc00::1", "fd00::1", "fe80::1", "2001:4860:4860::8888"]) {
      expect(() => validateMonitorUrl("http://[" + address + "]"), address).toThrow("IP_NOT_ALLOWED");
    }
  });

  it("rejects excessively long URLs", () => {
    expect(() => validateMonitorUrl("https://example.com/" + "a".repeat(2048))).toThrow("URL_TOO_LONG");
  });
});
