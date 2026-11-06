import { describe, expect, it } from "vitest";
import { canDeleteMonitors, canReadOrganization, canWriteMonitors } from "../src/authorization";

describe("organization role permissions", () => {
  it.each(["owner", "admin", "member", "viewer"])("allows %s to read their organization", role => {
    expect(canReadOrganization(role)).toBe(true);
  });

  it.each(["owner", "admin", "member"])("allows %s to create and update monitors", role => {
    expect(canWriteMonitors(role)).toBe(true);
  });

  it("does not allow viewers to create or update monitors", () => {
    expect(canWriteMonitors("viewer")).toBe(false);
  });

  it.each(["owner", "admin"])("allows %s to delete monitors", role => {
    expect(canDeleteMonitors(role)).toBe(true);
  });

  it.each(["member", "viewer", "unknown"])("does not allow %s to delete monitors", role => {
    expect(canDeleteMonitors(role)).toBe(false);
  });

  it("rejects unknown roles for organization access", () => {
    expect(canReadOrganization("root")).toBe(false);
  });
});
