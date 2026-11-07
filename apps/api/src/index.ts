import { validateMonitorUrl } from "../../../packages/monitoring-core/src/url-safety";
import { hashPassword, verifyPassword } from "../../../packages/auth-core/src/password";
import { canDeleteMonitors, canWriteMonitors, canAssignRole, canInviteRole, canRemoveMember, isOrganizationRole, canRemoveOwner } from "../../../packages/auth-core/src/authorization";

interface Env {
  DB: D1Database;
  APP_ENV: string;
  PUBLIC_APP_URL: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
}

type UserRow = { id: string; email: string; display_name: string | null; email_verified_at: string | null };
const encoder = new TextEncoder();
const json = (data: unknown, status = 200, headers: HeadersInit = {}): Response =>
  Response.json(data, { status, headers: { "cache-control": "no-store", ...headers } });
const id = () => crypto.randomUUID();
const b64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
const randomToken = () => b64url(crypto.getRandomValues(new Uint8Array(32)));
const hex = (bytes: ArrayBuffer) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (value: string) => hex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
const isoAfter = (seconds: number) => new Date(Date.now() + seconds * 1000).toISOString();
const cleanText = (value: unknown, max: number) => typeof value === "string" ? value.trim().slice(0, max) : "";
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const slugify = (value: string) => value.toLowerCase().normalize("NFKD").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "workspace";

async function sendEmail(env: Env, to: string, subject: string, html: string, key: string): Promise<boolean> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return false;
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json", "Idempotency-Key": key, "User-Agent": "ZetuWatch/0.1" },
      body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, html })
    });
    return response.ok;
  } catch { return false; }
}
function cookie(name: string, value: string, maxAge: number, secure: boolean): string {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}
function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") || "";
  const match = header.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  if (!match) return null;
  try { return decodeURIComponent(match.slice(name.length + 1)); } catch { return null; }
}
async function rateLimit(request: Request, env: Env, route: string, limit: number): Promise<boolean> {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const key = await sha256(`${route}:${ip}`);
  const now = Math.floor(Date.now() / 1000);
  const row = await env.DB.prepare(`INSERT INTO auth_rate_limits (key_hash, window_started_at, attempts)
    VALUES (?, ?, 1)
    ON CONFLICT(key_hash) DO UPDATE SET
      attempts = CASE WHEN auth_rate_limits.window_started_at <= ? THEN 1 ELSE auth_rate_limits.attempts + 1 END,
      window_started_at = CASE WHEN auth_rate_limits.window_started_at <= ? THEN excluded.window_started_at ELSE auth_rate_limits.window_started_at END,
      updated_at = CURRENT_TIMESTAMP
    RETURNING attempts`).bind(key, now, now - 900, now - 900).first<{ attempts: number }>();
  return (row?.attempts ?? limit + 1) <= limit;
}
async function currentUser(request: Request, env: Env): Promise<UserRow | null> {
  const raw = readCookie(request, "zw_session");
  if (!raw) return null;
  const tokenHash = await sha256(raw);
  const row = await env.DB.prepare(`SELECT u.id, u.email, u.display_name, u.email_verified_at
    FROM auth_sessions s JOIN users u ON u.id = s.user_id
    WHERE s.token_hash = ? AND s.expires_at > ? AND u.email_verified_at IS NOT NULL`)
    .bind(tokenHash, new Date().toISOString()).first<UserRow>();
  if (row) await env.DB.prepare("UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ?").bind(tokenHash).run();
  return row;
}
function originAllowed(request: Request, env: Env): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try { return new URL(origin).origin === new URL(env.PUBLIC_APP_URL).origin; } catch { return false; }
}
function htmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const response = await (async (): Promise<Response> => {
    if (request.method === "OPTIONS") {
      if (!originAllowed(request, env)) return json({ error: "ORIGIN_NOT_ALLOWED" }, 403);
      return new Response(null, { status: 204 });
    }
    const url = new URL(request.url);
    const secure = env.APP_ENV === "production";

    if (request.method === "GET" && url.pathname === "/health") {
      return json({ service: "zetuwatch-api", status: "ok", environment: env.APP_ENV });
    }

    if (["POST", "PATCH", "PUT", "DELETE"].includes(request.method) && !originAllowed(request, env)) {
      return json({ error: "ORIGIN_NOT_ALLOWED" }, 403);
    }

    if (request.method === "POST" && url.pathname === "/auth/register") {
      if (!(await rateLimit(request, env, "register", 5))) return json({ error: "RATE_LIMITED" }, 429);
      if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return json({ error: "EMAIL_PROVIDER_NOT_CONFIGURED" }, 503);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const email = cleanText(body?.email, 254).toLowerCase();
      const name = cleanText(body?.name, 80);
      const password = typeof body?.password === "string" ? body.password : "";
      const workspace = cleanText(body?.workspaceName, 80) || (name ? `${name}'s workspace` : "My workspace");
      if (!emailPattern.test(email) || password.length < 12 || password.length > 128 || !name) {
        return json({ error: "INVALID_INPUT", message: "Provide a valid email, name and password of 12–128 characters." }, 400);
      }
      const existing = await env.DB.prepare("SELECT id, display_name, email_verified_at FROM users WHERE email = ?")
        .bind(email).first<{ id: string; display_name: string | null; email_verified_at: string | null }>();
      if (existing) {
        if (!existing.email_verified_at) {
          const token = randomToken();
          await env.DB.prepare("INSERT INTO auth_tokens (id, user_id, token_hash, purpose, expires_at) VALUES (?, ?, ?, 'verify_email', ?)")
            .bind(id(), existing.id, await sha256(token), isoAfter(86400)).run();
          const link = `${env.PUBLIC_APP_URL.replace(/\/$/, "")}/auth.html?token=${encodeURIComponent(token)}`;
          await sendEmail(env, email, "Verify your ZetuWatch email", `<p>Hi ${htmlEscape(existing.display_name || "there")},</p><p><a href="${link}">Verify your email address</a></p><p>This link expires in 24 hours.</p>`, `verify-resend-${existing.id}-${await sha256(token)}`);
        }
        return json({ message: "If this address can be registered, a verification email will be sent. Check your inbox." }, 202);
      }
      const userId = id(), orgId = id(), token = randomToken(), tokenHash = await sha256(token);
      const passwordHash = await hashPassword(password);
      const orgSlug = `${slugify(workspace)}-${crypto.randomUUID().slice(0, 6)}`;
      try {
        await env.DB.batch([
          env.DB.prepare("INSERT INTO users (id, email, display_name, password_hash) VALUES (?, ?, ?, ?)").bind(userId, email, name, passwordHash),
          env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)").bind(orgId, workspace, orgSlug),
          env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'owner')").bind(orgId, userId),
          env.DB.prepare("INSERT INTO auth_tokens (id, user_id, token_hash, purpose, expires_at) VALUES (?, ?, ?, 'verify_email', ?)").bind(id(), userId, tokenHash, isoAfter(86400)),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'account.registered', 'user', ?)").bind(id(), orgId, userId, userId)
        ]);
      } catch {
        return json({ error: "REGISTRATION_FAILED" }, 400);
      }
      const verifyUrl = `${env.PUBLIC_APP_URL.replace(/\/$/, "")}/auth.html?token=${encodeURIComponent(token)}`;
      await sendEmail(env, email, "Verify your ZetuWatch email", `<p>Hi ${htmlEscape(name)},</p><p>Confirm your email address to activate your ZetuWatch account.</p><p><a href="${verifyUrl}">Verify email address</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p>`, `verify-${userId}`);
      return json({ message: "If this address can be registered, a verification email will be sent. Check your inbox." }, 202);
    }

    if (request.method === "POST" && url.pathname === "/auth/verify") {
      if (!(await rateLimit(request, env, "verify", 10))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const token = cleanText(body?.token, 128);
      if (token.length < 32) return json({ error: "INVALID_OR_EXPIRED_TOKEN" }, 400);
      const tokenHash = await sha256(token);
      const row = await env.DB.prepare(`UPDATE auth_tokens SET consumed_at = CURRENT_TIMESTAMP
        WHERE token_hash = ? AND purpose = 'verify_email' AND consumed_at IS NULL AND expires_at > ?
        RETURNING user_id`).bind(tokenHash, new Date().toISOString()).first<{ user_id: string }>();
      if (!row) return json({ error: "INVALID_OR_EXPIRED_TOKEN" }, 400);
      await env.DB.prepare("UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?")
        .bind(row.user_id).run();
      return json({ message: "Email verified. You can now sign in." });
    }

    if (request.method === "POST" && url.pathname === "/auth/resend-verification") {
      if (!(await rateLimit(request, env, "resend-verification", 5))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const email = cleanText(body?.email, 254).toLowerCase();
      const user = await env.DB.prepare("SELECT id, display_name, email_verified_at FROM users WHERE email = ?")
        .bind(email).first<{ id: string; display_name: string | null; email_verified_at: string | null }>();
      if (user && !user.email_verified_at && env.RESEND_API_KEY && env.EMAIL_FROM) {
        const token = randomToken();
        await env.DB.prepare("INSERT INTO auth_tokens (id, user_id, token_hash, purpose, expires_at) VALUES (?, ?, ?, 'verify_email', ?)")
          .bind(id(), user.id, await sha256(token), isoAfter(86400)).run();
        const link = `${env.PUBLIC_APP_URL.replace(/\/$/, "")}/auth.html?token=${encodeURIComponent(token)}`;
        await sendEmail(env, email, "Verify your ZetuWatch email", `<p>Hi ${htmlEscape(user.display_name || "there")},</p><p><a href="${link}">Verify your email address</a></p><p>This link expires in 24 hours.</p>`, `verify-resend-${user.id}-${await sha256(token)}`);
      }
      return json({ message: "If this account needs verification, a new link will be sent." }, 202);
    }

    if (request.method === "POST" && url.pathname === "/auth/password-reset/request") {
      if (!(await rateLimit(request, env, "password-reset", 5))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const email = cleanText(body?.email, 254).toLowerCase();
      const user = await env.DB.prepare("SELECT id, email_verified_at FROM users WHERE email = ?")
        .bind(email).first<{ id: string; email_verified_at: string | null }>();
      if (user?.email_verified_at && env.RESEND_API_KEY && env.EMAIL_FROM) {
        const token = randomToken();
        await env.DB.prepare("INSERT INTO auth_tokens (id, user_id, token_hash, purpose, expires_at) VALUES (?, ?, ?, 'password_reset', ?)")
          .bind(id(), user.id, await sha256(token), isoAfter(3600)).run();
        const link = `${env.PUBLIC_APP_URL.replace(/\/$/, "")}/reset-password.html?token=${encodeURIComponent(token)}`;
        await sendEmail(env, email, "Reset your ZetuWatch password", `<p>We received a request to reset your password.</p><p><a href="${link}">Choose a new password</a></p><p>This link expires in one hour. If you did not request this, ignore this email.</p>`, `password-reset-${user.id}-${await sha256(token)}`);
      }
      return json({ message: "If a verified account exists for that address, password reset instructions will be sent." }, 202);
    }

    if (request.method === "POST" && url.pathname === "/auth/password-reset/confirm") {
      if (!(await rateLimit(request, env, "password-reset-confirm", 8))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const token = cleanText(body?.token, 128);
      const password = typeof body?.password === "string" ? body.password : "";
      if (token.length < 32 || password.length < 12 || password.length > 128) return json({ error: "INVALID_INPUT" }, 400);
      // Derive the new hash before consuming the one-time token. If the
      // crypto operation fails or exceeds the runtime budget, the user can
      // still use the same reset link instead of being locked out.
      const passwordHash = await hashPassword(password);
      const tokenHash = await sha256(token);
      const row = await env.DB.prepare(`UPDATE auth_tokens SET consumed_at = CURRENT_TIMESTAMP
        WHERE token_hash = ? AND purpose = 'password_reset' AND consumed_at IS NULL AND expires_at > ?
        RETURNING user_id`).bind(tokenHash, new Date().toISOString()).first<{ user_id: string }>();
      if (!row) return json({ error: "INVALID_OR_EXPIRED_TOKEN" }, 400);
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(passwordHash, row.user_id),
        env.DB.prepare("DELETE FROM auth_sessions WHERE user_id = ?").bind(row.user_id)
      ]);
      return json({ message: "Password updated. Sign in with your new password." });
    }

    if (request.method === "POST" && url.pathname === "/auth/login") {
      if (!(await rateLimit(request, env, "login", 10))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const email = cleanText(body?.email, 254).toLowerCase();
      const password = typeof body?.password === "string" ? body.password : "";
      if (password.length === 0 || password.length > 128) return json({ error: "INVALID_CREDENTIALS" }, 401);
      const row = await env.DB.prepare("SELECT id, email, display_name, email_verified_at, password_hash FROM users WHERE email = ?")
        .bind(email).first<UserRow & { password_hash: string | null }>();
      const valid = row?.password_hash ? await verifyPassword(password, row.password_hash) : false;
      if (!row || !valid) return json({ error: "INVALID_CREDENTIALS" }, 401);
      if (!row.email_verified_at) return json({ error: "EMAIL_NOT_VERIFIED" }, 403);
      const token = randomToken(), tokenHash = await sha256(token), sessionId = id();
      await env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
        .bind(sessionId, row.id, tokenHash, isoAfter(60 * 60 * 24 * 30)).run();
      return json({ user: { id: row.id, email: row.email, name: row.display_name } }, 200, {
        "set-cookie": cookie("zw_session", token, 60 * 60 * 24 * 30, secure)
      });
    }

    if (request.method === "POST" && url.pathname === "/auth/logout") {
      const raw = readCookie(request, "zw_session");
      if (raw) await env.DB.prepare("DELETE FROM auth_sessions WHERE token_hash = ?").bind(await sha256(raw)).run();
      return json({ message: "Signed out." }, 200, { "set-cookie": cookie("zw_session", "", 0, secure) });
    }

    if (request.method === "GET" && url.pathname === "/auth/me") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const organizations = await env.DB.prepare(`SELECT o.id, o.name, o.slug, m.role
        FROM organization_members m JOIN organizations o ON o.id = m.organization_id
        WHERE m.user_id = ? ORDER BY o.created_at`).bind(user.id).all();
      return json({ user: { id: user.id, email: user.email, name: user.display_name }, organizations: organizations.results });
    }


    // Team management: all routes are scoped through a verified organization membership.
    const teamMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/(members|invitations)(?:\/([0-9a-f-]{36}))?$/i);
    if (teamMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const organizationId = teamMatch[1];
      const resource = teamMatch[2];
      const targetId = teamMatch[3];
      const actor = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!actor) return json({ error: "FORBIDDEN" }, 403);

      if (resource === "members" && request.method === "GET" && !targetId) {
        const rows = await env.DB.prepare("SELECT u.id, u.email, u.display_name, m.role, m.created_at FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.organization_id = ? ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'member' THEN 2 ELSE 3 END, m.created_at ASC")
          .bind(organizationId).all();
        return json({ members: rows.results });
      }

      if (resource === "invitations" && request.method === "GET" && !targetId) {
        if (!canInviteRole(actor.role, "member")) return json({ error: "FORBIDDEN" }, 403);
        const rows = await env.DB.prepare("SELECT id, email, role, expires_at, created_at FROM organization_invitations WHERE organization_id = ? AND accepted_at IS NULL AND expires_at > ? ORDER BY created_at DESC")
          .bind(organizationId, new Date().toISOString()).all();
        return json({ invitations: rows.results });
      }

      if (resource === "invitations" && request.method === "POST" && !targetId) {
        if (!canInviteRole(actor.role, "member")) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "team-invite", 20))) return json({ error: "RATE_LIMITED" }, 429);
        if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return json({ error: "EMAIL_PROVIDER_NOT_CONFIGURED" }, 503);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const email = cleanText(body?.email, 254).toLowerCase();
        const role = cleanText(body?.role, 16) || "member";
        if (!emailPattern.test(email) || !isOrganizationRole(role) || !canInviteRole(actor.role, role)) {
          return json({ error: "INVALID_INVITATION" }, 400);
        }
        const existing = await env.DB.prepare("SELECT 1 FROM organization_members m JOIN users u ON u.id = m.user_id WHERE m.organization_id = ? AND lower(u.email) = ?")
          .bind(organizationId, email).first();
        if (existing) return json({ error: "ALREADY_A_MEMBER" }, 409);
        const pending = await env.DB.prepare("SELECT id FROM organization_invitations WHERE organization_id = ? AND lower(email) = ? AND accepted_at IS NULL AND expires_at > ?")
          .bind(organizationId, email, new Date().toISOString()).first();
        if (pending) return json({ error: "INVITATION_ALREADY_PENDING" }, 409);
        const token = randomToken();
        const invitationId = id();
        const tokenHash = await sha256(token);
        const expiresAt = isoAfter(7 * 86400);
        const organization = await env.DB.prepare("SELECT name FROM organizations WHERE id = ?")
          .bind(organizationId).first<{ name: string }>();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(invitationId, organizationId, email, role, tokenHash, user.id, expiresAt),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'team.invitation_created', 'invitation', ?)")
            .bind(id(), organizationId, user.id, invitationId)
        ]);
        const acceptUrl = env.PUBLIC_APP_URL.replace(/\/$/, "") + "/auth.html?invite=" + encodeURIComponent(token);
        const sent = await sendEmail(env, email, "Invitation to " + (organization?.name || "a ZetuWatch workspace"),
          "<p>You have been invited to join <strong>" + htmlEscape(organization?.name || "a ZetuWatch workspace") + "</strong> as " + htmlEscape(role) + ".</p><p><a href=\"" + acceptUrl + "\">Accept invitation</a></p><p>This invitation expires in seven days. Sign in or create an account using this email address before accepting.</p>",
          "team-invite-" + invitationId);
        if (!sent) {
          await env.DB.prepare("DELETE FROM organization_invitations WHERE id = ?").bind(invitationId).run();
          return json({ error: "INVITATION_EMAIL_FAILED" }, 502);
        }
        return json({ message: "Invitation sent.", invitation: { id: invitationId, email, role, expiresAt } }, 201);
      }

      if (resource === "members" && targetId && request.method === "PATCH") {
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const nextRole = cleanText(body?.role, 16);
        if (!isOrganizationRole(nextRole) || !canAssignRole(actor.role, nextRole)) return json({ error: "FORBIDDEN" }, 403);
        const target = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
          .bind(organizationId, targetId).first<{ role: string }>();
        if (!target) return json({ error: "MEMBER_NOT_FOUND" }, 404);
        if (targetId === user.id && nextRole !== "owner") return json({ error: "CANNOT_DEMOTE_SELF" }, 409);
        const changed = await env.DB.batch([
          env.DB.prepare("UPDATE organization_members SET role = ? WHERE organization_id = ? AND user_id = ? AND role <> ? AND (role <> 'owner' OR ? = 'owner' OR (SELECT COUNT(*) FROM organization_members WHERE organization_id = ? AND role = 'owner') > 1)")
            .bind(nextRole, organizationId, targetId, nextRole, nextRole, organizationId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) SELECT ?, ?, ?, 'team.member_role_changed', 'user', ?, ? WHERE changes() > 0")
            .bind(id(), organizationId, user.id, targetId, JSON.stringify({ from: target.role, to: nextRole }))
        ]);
        if ((changed[0] as D1Result).meta?.changes !== 1) {
          return json({ error: target.role === nextRole ? "ROLE_UNCHANGED" : "LAST_OWNER_REQUIRED" }, 409);
        }
        return json({ message: "Member role updated." });
      }

      if (resource === "members" && targetId && request.method === "DELETE") {
        const target = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
          .bind(organizationId, targetId).first<{ role: string }>();
        if (!target) return json({ error: "MEMBER_NOT_FOUND" }, 404);
        if (!canRemoveMember(actor.role, target.role, targetId === user.id)) return json({ error: "FORBIDDEN" }, 403);
        const removed = await env.DB.batch([
          env.DB.prepare("DELETE FROM organization_members WHERE organization_id = ? AND user_id = ? AND (role <> 'owner' OR (SELECT COUNT(*) FROM organization_members WHERE organization_id = ? AND role = 'owner') > 1)")
            .bind(organizationId, targetId, organizationId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'team.member_removed', 'user', ? WHERE changes() > 0")
            .bind(id(), organizationId, user.id, targetId)
        ]);
        if ((removed[0] as D1Result).meta?.changes !== 1) return json({ error: "LAST_OWNER_REQUIRED" }, 409);
        return json({ message: "Member removed from workspace." });
      }
    }

    if (request.method === "POST" && url.pathname === "/v1/invitations/accept") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (!(await rateLimit(request, env, "invitation-accept", 10))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const token = cleanText(body?.token, 128);
      if (token.length < 32) return json({ error: "INVALID_OR_EXPIRED_INVITATION" }, 400);
      const tokenHash = await sha256(token);
      const invitation = await env.DB.prepare("SELECT id, organization_id, email, role FROM organization_invitations WHERE token_hash = ? AND accepted_at IS NULL AND expires_at > ?")
        .bind(tokenHash, new Date().toISOString()).first<{ id: string; organization_id: string; email: string; role: string }>();
      if (!invitation || invitation.email.toLowerCase() !== user.email.toLowerCase()) return json({ error: "INVALID_OR_EXPIRED_INVITATION" }, 400);
      const results = await env.DB.batch([
        env.DB.prepare("UPDATE organization_invitations SET accepted_at = CURRENT_TIMESTAMP WHERE id = ? AND accepted_at IS NULL AND expires_at > ?")
          .bind(invitation.id, new Date().toISOString()),
        env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) SELECT ?, ?, ? WHERE changes() > 0 ON CONFLICT(organization_id, user_id) DO NOTHING")
          .bind(invitation.organization_id, user.id, invitation.role),
        env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'team.invitation_accepted', 'invitation', ? WHERE changes() > 0")
          .bind(id(), invitation.organization_id, user.id, invitation.id)
      ]);
      if ((results[0] as D1Result).meta?.changes !== 1) return json({ error: "INVITATION_ALREADY_USED" }, 409);
      return json({ message: "You joined the workspace.", organizationId: invitation.organization_id, role: invitation.role });
    }

    if (request.method === "GET" && url.pathname === "/v1/monitors") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const organizationId = cleanText(url.searchParams.get("organizationId"), 64);
      if (!organizationId) return json({ error: "ORGANIZATION_REQUIRED" }, 400);
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);
      const result = await env.DB.prepare(`SELECT id, name, monitor_type, target_url, method, expected_status,
        interval_seconds, timeout_ms, is_enabled, consecutive_failures, last_checked_at, next_check_at, created_at, updated_at
        FROM monitors WHERE organization_id = ? ORDER BY created_at DESC LIMIT 100`).bind(organizationId).all();
      return json({ monitors: result.results, executionEnabled: false, note: "Scheduled checks are not enabled yet; monitors are saved but have not been probed." });
    }

    if (request.method === "POST" && url.pathname === "/v1/monitors") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (!(await rateLimit(request, env, "monitor-create", 30))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const organizationId = cleanText(body?.organizationId, 64);
      const name = cleanText(body?.name, 80);
      const target = cleanText(body?.targetUrl, 2048);
      const monitorType = body?.monitorType === "api" ? "api" : body?.monitorType === "http" || !body?.monitorType ? "http" : "";
      const method = typeof body?.method === "string" ? body.method.toUpperCase() : "GET";
      const expectedStatus = Number(body?.expectedStatus ?? 200);
      const intervalSeconds = Number(body?.intervalSeconds ?? 300);
      const timeoutMs = Number(body?.timeoutMs ?? 10000);
      if (!organizationId || !name || !target || !monitorType ||
          !["GET", "HEAD"].includes(method) ||
          !Number.isInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599 ||
          !Number.isInteger(intervalSeconds) || intervalSeconds < 60 || intervalSeconds > 3600 ||
          !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) {
        return json({ error: "INVALID_MONITOR_INPUT", message: "Check the name, URL, monitor type, method, expected status, interval and timeout." }, 400);
      }
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!membership || !canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
      try { validateMonitorUrl(target); } catch (error) {
        return json({ error: "UNSAFE_OR_INVALID_URL", message: error instanceof Error ? error.message : "The URL is not allowed." }, 400);
      }
      const monitorId = id();
      await env.DB.batch([
        env.DB.prepare(`INSERT INTO monitors (id, organization_id, name, monitor_type, target_url, method, expected_status,
          interval_seconds, timeout_ms, is_enabled, next_check_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, CURRENT_TIMESTAMP)`)
          .bind(monitorId, organizationId, name, monitorType, target, method, expectedStatus, intervalSeconds, timeoutMs),
        env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'monitor.created', 'monitor', ?)")
          .bind(id(), organizationId, user.id, monitorId)
      ]);
      return json({ monitor: { id: monitorId, organizationId, name, monitorType, targetUrl: target, method, expectedStatus, intervalSeconds, timeoutMs, state: "awaiting_first_check" }, executionEnabled: false }, 201);
    }

    const monitorMatch = url.pathname.match(/^\/v1\/monitors\/([0-9a-f-]{36})(\/checks)?$/i);
    if (monitorMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const monitorId = monitorMatch[1];
      const monitor = await env.DB.prepare("SELECT id, organization_id, name, target_url, monitor_type, method, expected_status, interval_seconds, timeout_ms, is_enabled FROM monitors WHERE id = ?")
        .bind(monitorId).first<{ id: string; organization_id: string; name: string; target_url: string; monitor_type: string; method: string; expected_status: number; interval_seconds: number; timeout_ms: number; is_enabled: number }>();
      if (!monitor) return json({ error: "NOT_FOUND" }, 404);
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(monitor.organization_id, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);

      if (request.method === "GET" && monitorMatch[2] === "/checks") {
        const checks = await env.DB.prepare(`SELECT id, checked_at, is_up, status_code, response_time_ms, error_code
          FROM monitor_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 100`).bind(monitorId).all();
        return json({ checks: checks.results, executionEnabled: false });
      }
      if (request.method === "GET") return json({ monitor, state: "awaiting_first_check", executionEnabled: false });
      if (request.method === "PATCH") {
        if (!canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const name = body?.name === undefined ? monitor.name : cleanText(body.name, 80);
        const target = body?.targetUrl === undefined ? monitor.target_url : cleanText(body.targetUrl, 2048);
        const method = body?.method === undefined ? monitor.method : cleanText(body.method, 8).toUpperCase();
        const expectedStatus = body?.expectedStatus === undefined ? monitor.expected_status : Number(body.expectedStatus);
        const intervalSeconds = body?.intervalSeconds === undefined ? monitor.interval_seconds : Number(body.intervalSeconds);
        const timeoutMs = body?.timeoutMs === undefined ? monitor.timeout_ms : Number(body.timeoutMs);
        if (!name || !target || !["GET", "HEAD"].includes(method) ||
            !Number.isInteger(expectedStatus) || expectedStatus < 100 || expectedStatus > 599 ||
            !Number.isInteger(intervalSeconds) || intervalSeconds < 60 || intervalSeconds > 3600 ||
            !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 30000) return json({ error: "INVALID_MONITOR_INPUT" }, 400);
        try { validateMonitorUrl(target); } catch (error) {
          return json({ error: "UNSAFE_OR_INVALID_URL", message: error instanceof Error ? error.message : "The URL is not allowed." }, 400);
        }
        await env.DB.batch([
          env.DB.prepare(`UPDATE monitors SET name = ?, target_url = ?, method = ?, expected_status = ?,
            interval_seconds = ?, timeout_ms = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ?`)
            .bind(name, target, method, expectedStatus, intervalSeconds, timeoutMs, monitorId, monitor.organization_id),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'monitor.updated', 'monitor', ?)")
            .bind(id(), monitor.organization_id, user.id, monitorId)
        ]);
        return json({ message: "Monitor updated.", executionEnabled: false });
      }
      if (request.method === "DELETE") {
        if (!canDeleteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        await env.DB.batch([
          env.DB.prepare("DELETE FROM monitors WHERE id = ? AND organization_id = ?").bind(monitorId, monitor.organization_id),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'monitor.deleted', 'monitor', ?)")
            .bind(id(), monitor.organization_id, user.id, monitorId)
        ]);
        return json({ message: "Monitor deleted." });
      }
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }

    return json({ error: "NOT_FOUND" }, 404);
    })();

    const headers = new Headers(response.headers);
    const origin = request.headers.get("origin");
    if (origin && originAllowed(request, env)) {
      headers.set("access-control-allow-origin", origin);
      headers.set("access-control-allow-credentials", "true");
      headers.set("access-control-allow-methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS");
      headers.set("access-control-allow-headers", "Content-Type");
      headers.append("vary", "Origin");
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
};
