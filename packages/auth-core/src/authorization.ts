export type OrganizationRole = "owner" | "admin" | "member" | "viewer";

export function canReadOrganization(role: string): role is OrganizationRole {
  return role === "owner" || role === "admin" || role === "member" || role === "viewer";
}

export function canWriteMonitors(role: string): boolean {
  return role === "owner" || role === "admin" || role === "member";
}

export function canDeleteMonitors(role: string): boolean {
  return role === "owner" || role === "admin";
}
