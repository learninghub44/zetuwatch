import { describe, expect, it } from "vitest";
import {
  canAssignRole, canDeleteMonitors, canInviteRole, canReadOrganization, canRemoveOwner,
  canRemoveMember, canWriteMonitors, isOrganizationRole
} from "../src/authorization";

describe("organization role permissions", () => {
  it.each(["owner", "admin", "member", "viewer"])("allows %s to read their organization", role => {
    expect(canReadOrganization(role)).toBe(true);
  });
  it.each(["owner", "admin", "member"])("allows %s to create and update monitors", role => {
    expect(canWriteMonitors(role)).toBe(true);
  });
  it("does not allow viewers to create or update monitors", () => expect(canWriteMonitors("viewer")).toBe(false));
  it.each(["owner", "admin"])("allows %s to delete monitors", role => expect(canDeleteMonitors(role)).toBe(true));
  it.each(["member", "viewer", "unknown"])("does not allow %s to delete monitors", role => expect(canDeleteMonitors(role)).toBe(false));
  it("rejects unknown roles", () => {
    expect(canReadOrganization("root")).toBe(false);
    expect(isOrganizationRole("root")).toBe(false);
  });
});

describe("team administration policy", () => {
  it("allows owners to assign any role", () => {
    expect(canAssignRole("owner", "admin")).toBe(true);
    expect(canAssignRole("owner", "member")).toBe(true);
    expect(canAssignRole("owner", "viewer")).toBe(true);
  });
  it("prevents admins from granting elevated roles", () => {
    expect(canAssignRole("admin", "member")).toBe(true);
    expect(canAssignRole("admin", "viewer")).toBe(true);
    expect(canAssignRole("admin", "owner")).toBe(false);
    expect(canAssignRole("admin", "admin")).toBe(false);
  });
  it("allows admins to invite only member/viewer roles", () => {
    expect(canInviteRole("admin", "member")).toBe(true);
    expect(canInviteRole("admin", "viewer")).toBe(true);
    expect(canInviteRole("admin", "admin")).toBe(false);
    expect(canInviteRole("member", "viewer")).toBe(false);
  });
  it("allows members to leave but not remove other members", () => {
    expect(canRemoveMember("member", "member", true)).toBe(true);
    expect(canRemoveMember("member", "viewer", false)).toBe(false);
    expect(canRemoveMember("member", "owner", true)).toBe(false);
  });
  it("prevents admins from removing owners or admins", () => {
    expect(canRemoveMember("admin", "member", false)).toBe(true);
    expect(canRemoveMember("admin", "viewer", false)).toBe(true);
    expect(canRemoveMember("admin", "owner", false)).toBe(false);
    expect(canRemoveMember("admin", "admin", false)).toBe(false);
  });
  it("prevents owners from deleting another owner through member removal", () => {
    expect(canRemoveMember("owner", "admin", false)).toBe(true);
    expect(canRemoveMember("owner", "owner", false)).toBe(false);
  });
});

describe("workspace owner continuity", () => {
  it("requires another owner before an owner can be removed or demoted", () => {
    expect(canRemoveOwner(0)).toBe(false);
    expect(canRemoveOwner(1)).toBe(false);
    expect(canRemoveOwner(2)).toBe(true);
    expect(canRemoveOwner(3)).toBe(true);
  });
  it("rejects invalid owner counts", () => {
    expect(canRemoveOwner(-1)).toBe(false);
    expect(canRemoveOwner(1.5)).toBe(false);
  });
});
