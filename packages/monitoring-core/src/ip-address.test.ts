import { describe, expect, it } from "vitest";
import { assertPublicDnsAnswers, isIpv4Address, isPublicIpAddress } from "./ip-address";

describe("IP address classification", () => {
  it("accepts canonical public IPv4 and IPv6 addresses", () => {
    for (const address of ["1.1.1.1", "8.8.8.8", "93.184.216.34"]) {
      expect(isPublicIpAddress(address), address).toBe(true);
    }
    for (const address of ["2001:4860:4860::8888", "2606:4700:4700::1111"]) {
      expect(isPublicIpAddress(address), address).toBe(true);
    }
  });

  it("rejects non-public IPv4 special-purpose ranges", () => {
    const blocked = [
      "0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1",
      "169.254.169.254", "172.16.0.1", "172.31.255.254",
      "192.0.0.9", "192.0.2.1", "192.88.99.1", "192.168.1.1",
      "198.18.0.1", "198.19.255.254", "198.51.100.1",
      "203.0.113.1", "224.0.0.1", "239.255.255.255",
      "240.0.0.1", "255.255.255.255"
    ];
    for (const address of blocked) {
      expect(isPublicIpAddress(address), address).toBe(false);
    }
  });

  it("allows only conservative global-unicast IPv6 ranges", () => {
    const blocked = [
      "::", "::1", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
      "64:ff9b::808:808", "fc00::1", "fd00::1", "fe80::1",
      "fec0::1", "ff02::1", "2001::1", "2001:db8::1",
      "2002:0808:0808::1", "3fff::1"
    ];
    for (const address of blocked) {
      expect(isPublicIpAddress(address), address).toBe(false);
    }
  });

  it("rejects malformed and non-canonical address representations", () => {
    for (const address of [
      "", "example.com", "127.1", "2130706433", "0177.0.0.1",
      "0x7f000001", "256.1.1.1", "1.2.3", "1.2.3.4.5",
      "2001:::1", "2001:db8::1::2", "2001:db8::gggg", "fe80::1%eth0"
    ]) {
      expect(isPublicIpAddress(address), address).toBe(false);
    }
    expect(isIpv4Address("1.1.1.1")).toBe(true);
    expect(isIpv4Address("001.1.1.1")).toBe(false);
  });
});

describe("assertPublicDnsAnswers", () => {
  it("returns a de-duplicated set when every A/AAAA answer is public", () => {
    expect(assertPublicDnsAnswers([
      "1.1.1.1", "2606:4700:4700::1111", "1.1.1.1"
    ])).toEqual(["1.1.1.1", "2606:4700:4700::1111"]);
  });

  it("rejects an answer set containing any private or special-use address", () => {
    expect(() => assertPublicDnsAnswers(["1.1.1.1", "127.0.0.1"]))
      .toThrow("DNS_NON_PUBLIC_ADDRESS");
    expect(() => assertPublicDnsAnswers(["2606:4700:4700::1111", "fe80::1"]))
      .toThrow("DNS_NON_PUBLIC_ADDRESS");
  });

  it("rejects empty, malformed and oversized DNS answer sets", () => {
    expect(() => assertPublicDnsAnswers([])).toThrow("DNS_NO_ADDRESSES");
    expect(() => assertPublicDnsAnswers(["not-an-ip"])).toThrow("DNS_NON_PUBLIC_ADDRESS");
    expect(() => assertPublicDnsAnswers(Array.from({ length: 17 }, () => "1.1.1.1")))
      .toThrow("DNS_TOO_MANY_ADDRESSES");
  });
});
