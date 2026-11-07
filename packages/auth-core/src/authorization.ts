export type OrganizationRole = "owner" | "admin" | "member" | "viewer";

const roles: readonly OrganizationRole[] = ["owner", "admin", "member", "viewer"];

export function isOrganizationRole(value: string): value is OrganizationRole {
  return roles.includes(value as OrganizationRole);
}

export function canReadOrganization(role: string): role is OrganizationRole {
  return isOrganizationRole(role);
}

export function canWriteMonitors(role: string): boolean {
  return role === "owner" || role === "admin" || role === "member";
}

export function canDeleteMonitors(role: string): boolean {
  return role === "owner" || role === "admin";
}

/** Only owners may grant/revoke administrator or owner access. */
export function canAssignRole(actorRole: string, nextRole: OrganizationRole): boolean {
  if (actorRole === "owner") return true;
  if (actorRole === "admin") return nextRole === "member" || nextRole === "viewer";
  return false;
}

/** Admins can invite members/viewers; owners can invite any non-owner role. */
export function canInviteRole(actorRole: string, invitedRole: OrganizationRole): boolean {
  if (actorRole === "owner") return invitedRole !== "owner";
  if (actorRole === "admin") return invitedRole === "member" || invitedRole === "viewer";
  return false;
}

/** Members may remove themselves; admins can remove non-admin/non-owner members. */
export function canRemoveMember(actorRole: string, targetRole: string, isSelf: boolean): boolean {
  if (isSelf) return targetRole !== "owner";
  if (actorRole === "owner") return targetRole !== "owner";
  if (actorRole === "admin") return targetRole === "member" || targetRole === "viewer";
  return false;
}
