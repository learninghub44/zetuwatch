import { afterEach, describe, expect, it, vi } from "vitest";
import { runHttpProbe } from "../src/http-probe";

describe("runHttpProbe", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("fails closed until SSRF-safe egress is available", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    await expect(runHttpProbe("https://example.com/health"))
      .rejects.toThrow("PROBE_EGRESS_NOT_HARDENED");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
