import { describe, expect, it, vi } from "vitest";
import { runHttpProbe } from "./http-probe";

describe("runHttpProbe", () => {
  it("fails closed until SSRF-safe egress is available", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch");
    await expect(runHttpProbe("https://example.com")).rejects.toThrow("PROBE_EGRESS_NOT_HARDENED");
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
  });
});
