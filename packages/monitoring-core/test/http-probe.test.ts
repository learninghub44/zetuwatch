import { afterEach, describe, expect, it, vi } from "vitest";
import { runHttpProbe } from "../src/http-probe";

describe("runHttpProbe", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reports a matching status as healthy", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(null, { status: 200 })));
    const result = await runHttpProbe("https://example.com/health");
    expect(result.isUp).toBe(true);
    expect(result.statusCode).toBe(200);
    expect(result.errorCode).toBeNull();
  });

  it("does not follow redirects", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(
      new Response(null, { status: 302, headers: { location: "http://127.0.0.1/" } })
    ));
    const result = await runHttpProbe("https://example.com");
    expect(result.isUp).toBe(false);
    expect(result.errorCode).toBe("REDIRECT_NOT_FOLLOWED");
  });

  it("returns a bounded network failure for rejected fetches", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("network")));
    const result = await runHttpProbe("https://example.com");
    expect(result.isUp).toBe(false);
    expect(result.errorCode).toBe("NETWORK_ERROR");
  });

  it("rejects methods outside GET and HEAD before making a request", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(runHttpProbe("https://example.com", "POST")).rejects.toThrow("METHOD_NOT_ALLOWED");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects invalid expected status codes", async () => {
    await expect(runHttpProbe("https://example.com", "GET", 99))
      .rejects.toThrow("EXPECTED_STATUS_INVALID");
  });

  it("does not call fetch for blocked destinations", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(runHttpProbe("http://127.0.0.1")).rejects.toThrow("IP_NOT_ALLOWED");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
