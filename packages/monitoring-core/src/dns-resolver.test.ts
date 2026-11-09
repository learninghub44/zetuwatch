import { describe, expect, it, vi } from "vitest";
import { resolvePublicHostname, type DnsFetcher } from "./dns-resolver";

function dnsResponse(
  answers: Array<{ type: number; data: string }>,
  options: { status?: number; truncated?: boolean; extra?: Record<string, unknown> } = {}
): Response {
  return new Response(JSON.stringify({
    Status: options.status ?? 0,
    TC: options.truncated ?? false,
    Answer: answers,
    ...options.extra
  }), { status: 200, headers: { "content-type": "application/dns-json" } });
}

function responseFor(
  records: { a?: string[]; aaaa?: string[]; aStatus?: number; aaaaStatus?: number }
): DnsFetcher {
  return async (input) => {
    const url = new URL(String(input));
    const type = url.searchParams.get("type");
    if (type === "1") {
      return dnsResponse((records.a || []).map(data => ({ type: 1, data })), { status: records.aStatus });
    }
    return dnsResponse((records.aaaa || []).map(data => ({ type: 28, data })), { status: records.aaaaStatus });
  };
}

describe("resolvePublicHostname", () => {
  it("resolves both record families and returns only a validated public set", async () => {
    const fetcher = vi.fn(responseFor({
      a: ["1.1.1.1"],
      aaaa: ["2606:4700:4700::1111"]
    }));

    const result = await resolvePublicHostname("Example.COM.", { fetcher });

    expect(result).toEqual(["1.1.1.1", "2606:4700:4700::1111"]);
    expect(fetcher).toHaveBeenCalledTimes(2);
    for (const call of fetcher.mock.calls) {
      expect(call[1]?.redirect).toBe("error");
      expect(new Headers(call[1]?.headers).get("accept")).toBe("application/dns-json");
    }
  });

  it("rejects the entire DNS result when either family contains a private address", async () => {
    await expect(resolvePublicHostname("example.com", {
      fetcher: responseFor({ a: ["1.1.1.1"], aaaa: ["fe80::1"] })
    })).rejects.toThrow("DNS_NON_PUBLIC_ADDRESS");
  });

  it("accepts a public A result when the AAAA query has no records", async () => {
    await expect(resolvePublicHostname("example.com", {
      fetcher: responseFor({ a: ["93.184.216.34"] })
    })).resolves.toEqual(["93.184.216.34"]);
  });

  it("fails closed when neither family returns an address", async () => {
    await expect(resolvePublicHostname("example.com", {
      fetcher: responseFor({})
    })).rejects.toThrow("DNS_NO_ADDRESSES");
  });

  it("rejects DNS errors, truncated responses and malformed payloads", async () => {
    await expect(resolvePublicHostname("example.com", {
      fetcher: responseFor({ aStatus: 2 })
    })).rejects.toThrow("DNS_LOOKUP_FAILED");

    await expect(resolvePublicHostname("example.com", {
      fetcher: async () => dnsResponse([], { truncated: true })
    })).rejects.toThrow("DNS_TRUNCATED_RESPONSE");

    await expect(resolvePublicHostname("example.com", {
      fetcher: async () => new Response("{", {
        status: 200,
        headers: { "content-type": "application/dns-json" }
      })
    })).rejects.toThrow("DNS_INVALID_RESPONSE");
  });

  it("rejects malformed answer entries instead of trusting their shape", async () => {
    const fetcher: DnsFetcher = async (input) => {
      const url = new URL(String(input));
      if (url.searchParams.get("type") === "1") {
        return new Response(JSON.stringify({ Status: 0, Answer: [null, { type: 1, data: "1.1.1.1" }] }), {
          headers: { "content-type": "application/dns-json" }
        });
      }
      return dnsResponse([]);
    };
    await expect(resolvePublicHostname("example.com", { fetcher })).rejects.toThrow("DNS_NON_PUBLIC_ADDRESS");
  });

  it("caps DNS response bodies and never follows redirects", async () => {
    await expect(resolvePublicHostname("example.com", {
      fetcher: async () => new Response(JSON.stringify({
        Status: 0,
        Answer: [],
        padding: "x".repeat(17 * 1024)
      }), { headers: { "content-type": "application/dns-json" } })
    })).rejects.toThrow("DNS_RESPONSE_TOO_LARGE");

    const fetcher = vi.fn(responseFor({ a: ["1.1.1.1"] }));
    await resolvePublicHostname("example.com", { fetcher });
    expect(fetcher.mock.calls.every(call => call[1]?.redirect === "error")).toBe(true);
  });

  it("rejects invalid, local and numeric hosts before making DNS requests", async () => {
    const fetcher = vi.fn(responseFor({ a: ["1.1.1.1"] }));
    for (const host of ["localhost", "service.internal", "127.0.0.1", "2130706433", "bad host"]) {
      await expect(resolvePublicHostname(host, { fetcher })).rejects.toThrow("DNS_HOST_NOT_ALLOWED");
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("enforces a bounded resolver timeout", async () => {
    const fetcher: DnsFetcher = async (_input, init) => new Promise((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
    });

    await expect(resolvePublicHostname("example.com", {
      fetcher,
      timeoutMs: 50
    })).rejects.toThrow("DNS_TIMEOUT");
  });

  it("rejects timeout values outside the supported bound", async () => {
    await expect(resolvePublicHostname("example.com", { timeoutMs: 10 }))
      .rejects.toThrow("DNS_TIMEOUT_INVALID");
    await expect(resolvePublicHostname("example.com", { timeoutMs: 6_000 }))
      .rejects.toThrow("DNS_TIMEOUT_INVALID");
  });
});
