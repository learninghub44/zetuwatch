import { validateMonitorUrl } from "../../../packages/monitoring-core/src/url-safety";
import { hashPassword, verifyPassword } from "../../../packages/auth-core/src/password";
import { canDeleteMonitors, canWriteMonitors, canAssignRole, canInviteRole, canRemoveMember, isOrganizationRole } from "../../../packages/auth-core/src/authorization";
import { dispatchDueMonitors, isProbeExecutionEnabled } from "../../../packages/scheduler-core/src/dispatch";
import { dispatchNotificationBatch } from "../../../packages/notifications-core/src/dispatch";

interface Env {
  DB: D1Database;
  APP_ENV: string;
  PUBLIC_APP_URL: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
  PROBES_ENABLED?: string;
  PROBE_AGENT_URL?: string;
  PROBE_SHARED_SECRET?: string;
}

type UserRow = { id: string; email: string; display_name: string | null; email_verified_at: string | null; authMethod?: "api_key"; apiKeyOrganizationId?: string; apiKeyScopes?: string[] };
type MonitorStateRow = {
  is_enabled: number;
  last_checked_at?: string | null;
  consecutive_failures?: number;
  last_check_is_up?: number | null;
  open_incident_status?: string | null;
};
function getMonitorState(monitor: MonitorStateRow, executionEnabled: boolean): string {
  if (Number(monitor.is_enabled) !== 1) return "paused";
  if (monitor.open_incident_status) return monitor.open_incident_status === "monitoring" ? "recovering" : "down";
  if (!executionEnabled) return "execution_disabled";
  if (!monitor.last_checked_at) return "awaiting_first_check";
  const lastCheckFailed = monitor.last_check_is_up !== null && monitor.last_check_is_up !== undefined &&
    Number(monitor.last_check_is_up) === 0;
  if (Number(monitor.consecutive_failures ?? 0) > 0 || lastCheckFailed) return "suspect";
  if (Number(monitor.last_check_is_up) === 1) return "healthy";
  return "unknown";
}
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
  // An explicit bearer credential takes precedence over ambient browser cookies.
  // This prevents a read-only API key from inheriting a more privileged session.
  const authorization = request.headers.get("authorization");
  if (authorization !== null) {
    const match = /^Bearer (zw_live_[A-Za-z0-9_-]{40,64})$/.exec(authorization);
    const secret = match?.[1];
    if (!secret || !(await rateLimit(request, env, "api-key-auth", 300))) return null;
    const tokenHash = await sha256(secret);
    const row = await env.DB.prepare("SELECT u.id, u.email, u.display_name, u.email_verified_at, k.organization_id AS api_key_organization_id FROM api_keys k JOIN users u ON u.id = k.created_by JOIN organization_members m ON m.organization_id = k.organization_id AND m.user_id = u.id WHERE k.key_hash = ? AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > ?) AND u.email_verified_at IS NOT NULL AND m.role IN ('owner', 'admin')")
      .bind(tokenHash, new Date().toISOString()).first<UserRow & { api_key_organization_id: string }>();
    if (!row) return null;
    await env.DB.prepare("UPDATE api_keys SET last_used_at = CURRENT_TIMESTAMP WHERE key_hash = ? AND revoked_at IS NULL").bind(tokenHash).run();
    return { id: row.id, email: row.email, display_name: row.display_name, email_verified_at: row.email_verified_at, authMethod: "api_key", apiKeyOrganizationId: row.api_key_organization_id, apiKeyScopes: ["read"] };
  }

  const raw = readCookie(request, "zw_session");
  if (!raw) return null;
  const tokenHash = await sha256(raw);
  const row = await env.DB.prepare("SELECT u.id, u.email, u.display_name, u.email_verified_at FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND s.expires_at > ? AND u.email_verified_at IS NOT NULL")
    .bind(tokenHash, new Date().toISOString()).first<UserRow>();
  if (row) await env.DB.prepare("UPDATE auth_sessions SET last_seen_at = CURRENT_TIMESTAMP WHERE token_hash = ?").bind(tokenHash).run();
  return row;
}
function apiKeyAllows(user: UserRow, organizationId: string, permission: "read" | "write" = "read"): boolean {
  if (user.authMethod !== "api_key") return true;
  return permission === "read" && user.apiKeyOrganizationId === organizationId && (user.apiKeyScopes || []).includes("read");
}
function originAllowed(request: Request, env: Env): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return true;
  try { return new URL(origin).origin === new URL(env.PUBLIC_APP_URL).origin; } catch { return false; }
}
function htmlEscape(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


function enqueueNotificationDeliveries(env: Env, eventId: string, eventType: string, now: string): D1PreparedStatement {
  return env.DB.prepare(`
    INSERT OR IGNORE INTO notification_deliveries
      (id, organization_id, incident_id, channel_id, provider, status,
       attempt_count, next_attempt_at, event_id, event_type, recipient_email, channel_created_by, updated_at)
    SELECT ? || ':' || c.id, m.organization_id, i.id, c.id, 'resend', 'queued',
      0, ?, e.id, e.event_type, c.destination, c.created_by, ?
    FROM incident_events e
    JOIN incidents i ON i.id = e.incident_id
    JOIN monitors m ON m.id = i.monitor_id
    JOIN notification_channels c ON c.organization_id = m.organization_id
    JOIN users u ON u.id = c.created_by
      AND u.email_verified_at IS NOT NULL
      AND lower(u.email) = lower(c.destination)
    JOIN organization_members om
      ON om.organization_id = m.organization_id AND om.user_id = u.id
    WHERE e.id = ? AND e.event_type = ?
      AND (e.event_type NOT IN ('incident.update', 'incident.status_changed') OR e.visibility = 'public')
      AND c.channel_type = 'email' AND c.is_enabled = 1
      AND c.verified_at IS NOT NULL
  `).bind(eventId, now, now, eventId, eventType);
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

    // Public status pages expose only explicitly published configuration and
    // customer-visible incident updates. Live health remains unknown until
    // the secure scheduled monitoring runner is enabled.
    const publicStatusMatch = url.pathname.match(/^\/public\/status-pages\/([a-z0-9-]{3,48})$/i);
    if (request.method === "GET" && publicStatusMatch) {
      const slug = publicStatusMatch[1].toLowerCase();
      const page = await env.DB.prepare(`SELECT id, name, slug, description, published_at AS publishedAt
        FROM status_pages
        WHERE slug = ? AND is_published = 1 AND archived_at IS NULL`)
        .bind(slug)
        .first<{ id: string; name: string; slug: string; description: string; publishedAt: string | null }>();
      if (!page) return json({ error: "NOT_FOUND" }, 404);

      const components = await env.DB.prepare(`SELECT m.name, m.monitor_type AS monitorType, m.is_enabled AS isEnabled
        FROM status_page_monitors spm
        JOIN monitors m ON m.id = spm.monitor_id
        WHERE spm.page_id = ? AND m.deleted_at IS NULL
        ORDER BY spm.position ASC, m.name ASC`)
        .bind(page.id)
        .all<{ name: string; monitorType: string; isEnabled: number }>();

      const updates = await env.DB.prepare(`SELECT
          m.name AS monitorName,
          e.message,
          e.created_at AS createdAt
        FROM status_page_monitors spm
        JOIN monitors m ON m.id = spm.monitor_id
        JOIN incidents i ON i.monitor_id = m.id
        JOIN incident_events e ON e.incident_id = i.id AND e.visibility = 'public'
        WHERE spm.page_id = ? AND m.deleted_at IS NULL
        ORDER BY e.created_at DESC, e.id DESC
        LIMIT 50`)
        .bind(page.id)
        .all();
      return json({
        page: { name: page.name, slug: page.slug, description: page.description, publishedAt: page.publishedAt },
        overallStatus: "unknown",
        monitoringEnabled: false,
        components: components.results.map(component => ({
          name: component.name,
          monitorType: component.monitorType,
          state: Number(component.isEnabled) === 1 ? "awaiting_first_check" : "paused",
          status: "unknown"
        })),
        updates: updates.results
      });
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
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
      const organizations = await env.DB.prepare(`SELECT o.id, o.name, o.slug, m.role
        FROM organization_members m JOIN organizations o ON o.id = m.organization_id
        WHERE m.user_id = ? ORDER BY o.created_at`).bind(user.id).all();
      return json({ user: { id: user.id, email: user.email, name: user.display_name }, organizations: organizations.results });
    }



    const apiKeyMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/api-keys(?:\/([0-9a-f-]{36}))?$/i);
    if (apiKeyMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
      const organizationId = apiKeyMatch[1];
      const keyId = apiKeyMatch[2];
      const actor = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!actor || !["owner", "admin"].includes(actor.role)) return json({ error: "FORBIDDEN" }, 403);

      if (request.method === "GET" && !keyId) {
        const rows = await env.DB.prepare("SELECT id, name, key_prefix, last_used_at, expires_at, revoked_at, created_at FROM api_keys WHERE organization_id = ? ORDER BY created_at DESC LIMIT 25")
          .bind(organizationId).all();
        return json({ apiKeys: rows.results });
      }

      if (request.method === "POST" && !keyId) {
        if (!(await rateLimit(request, env, "api-key-create", 10))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const name = cleanText(body?.name, 60);
        const expiresInDays = Number(body?.expiresInDays ?? 90);
        const hasControl = [...name].some(character => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
        if (!name || hasControl || ![30, 90, 365].includes(expiresInDays)) {
          return json({ error: "INVALID_API_KEY_INPUT", message: "Provide a name and an expiry of 30, 90 or 365 days." }, 400);
        }
        const active = await env.DB.prepare("SELECT COUNT(*) AS count FROM api_keys WHERE organization_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)")
          .bind(organizationId, new Date().toISOString()).first<{ count: number }>();
        if ((active?.count ?? 0) >= 10) return json({ error: "API_KEY_LIMIT_REACHED" }, 409);
        const keyId = id();
        const secret = "zw_live_" + randomToken();
        const keyPrefix = secret.slice(0, 16);
        const expiresAt = new Date(Date.now() + expiresInDays * 86400_000).toISOString();
        const keyHash = await sha256(secret);
        const createdAt = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare("INSERT INTO api_keys (id, organization_id, created_by, name, key_prefix, key_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(keyId, organizationId, user.id, name, keyPrefix, keyHash, expiresAt),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) VALUES (?, ?, ?, 'api_key.created', 'api_key', ?, ?)")
            .bind(id(), organizationId, user.id, keyId, JSON.stringify({ name, keyPrefix, expiresAt }))
        ]);
        return json({ apiKey: { id: keyId, name, keyPrefix, expiresAt, createdAt }, secret }, 201);
      }

      if (request.method === "DELETE" && keyId) {
        if (!(await rateLimit(request, env, "api-key-revoke", 30))) return json({ error: "RATE_LIMITED" }, 429);
        const results = await env.DB.batch([
          env.DB.prepare("UPDATE api_keys SET revoked_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND revoked_at IS NULL")
            .bind(keyId, organizationId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'api_key.revoked', 'api_key', ? WHERE changes() = 1")
            .bind(id(), organizationId, user.id, keyId),
          env.DB.prepare("SELECT id, revoked_at FROM api_keys WHERE id = ? AND organization_id = ?")
            .bind(keyId, organizationId)
        ]);
        const current = results[2]?.results?.[0] as { id: string; revoked_at: string | null } | undefined;
        if (!current) return json({ error: "NOT_FOUND" }, 404);
        const changed = (results[0] as D1Result).meta?.changes === 1;
        return json({ message: "API key revoked.", changed, revokedAt: current.revoked_at });
      }

      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }


    const statusPagesCollectionMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/status-pages$/i);
    if (statusPagesCollectionMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
      const organizationId = statusPagesCollectionMatch[1];
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);

      if (request.method === "GET") {
        const pages = await env.DB.prepare(`SELECT
            p.id, p.name, p.slug, p.description, p.is_published AS isPublished,
            p.published_at AS publishedAt, p.created_at AS createdAt,
            (SELECT COUNT(*) FROM status_page_monitors spm JOIN monitors cm ON cm.id = spm.monitor_id WHERE spm.page_id = p.id AND cm.deleted_at IS NULL) AS componentCount
          FROM status_pages p
          WHERE p.organization_id = ? AND p.archived_at IS NULL
          ORDER BY p.created_at DESC
          LIMIT 50`)
          .bind(organizationId).all();
        return json({ statusPages: pages.results });
      }

      if (request.method === "POST") {
        if (!["owner", "admin"].includes(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "status-page-create", 10))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const name = cleanText(body?.name, 80);
        const description = typeof body?.description === "string" ? body.description.trim() : "";
        const rawSlug = cleanText(body?.slug, 48).toLowerCase();
        const slug = rawSlug || (slugify(name).slice(0, 40) + "-" + crypto.randomUUID().slice(0, 6));
        const monitorIdsValue = body?.monitorIds === undefined ? [] : body.monitorIds;
        const monitorIds = Array.isArray(monitorIdsValue) ? monitorIdsValue : null;
        const slugPattern = /^[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])$/;
        const reservedSlugs = new Set(["admin", "api", "app", "auth", "health", "status", "status-pages"]);
        if (name.length < 2 || /[\u0000-\u001f\u007f]/.test(name) || description.length > 240 ||
            /[\u0000-\u001f\u007f]/.test(description) ||
            !slugPattern.test(slug) || reservedSlugs.has(slug) ||
            !monitorIds || monitorIds.length > 50 ||
            monitorIds.some(value => typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) ||
            new Set(monitorIds).size !== monitorIds.length) {
          return json({ error: "INVALID_STATUS_PAGE_INPUT" }, 400);
        }
        if (monitorIds.length) {
          const placeholders = monitorIds.map(() => "?").join(",");
          const valid = await env.DB.prepare(`SELECT COUNT(*) AS count FROM monitors
            WHERE organization_id = ? AND deleted_at IS NULL AND id IN (${placeholders})`)
            .bind(organizationId, ...monitorIds).first<{ count: number }>();
          if ((valid?.count ?? 0) !== monitorIds.length) {
            return json({ error: "INVALID_STATUS_PAGE_MONITORS" }, 400);
          }
        }
        const pageId = id();
        const statements = [
          env.DB.prepare("INSERT INTO status_pages (id, organization_id, name, slug, description, created_by) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(pageId, organizationId, name, slug, description, user.id),
          ...monitorIds.map((monitorId, position) =>
            env.DB.prepare("INSERT INTO status_page_monitors (page_id, monitor_id, position) VALUES (?, ?, ?)")
              .bind(pageId, monitorId, position)
          ),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) VALUES (?, ?, ?, 'status_page.created', 'status_page', ?, ?)")
            .bind(id(), organizationId, user.id, pageId, JSON.stringify({ slug, componentCount: monitorIds.length }))
        ];
        try {
          await env.DB.batch(statements);
        } catch {
          return json({ error: "STATUS_PAGE_SLUG_TAKEN" }, 409);
        }
        return json({
          statusPage: { id: pageId, name, slug, description, isPublished: false, componentCount: monitorIds.length },
          publicPath: "/status.html?slug=" + encodeURIComponent(slug)
        }, 201);
      }
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }

    const statusPageMatch = url.pathname.match(/^\/v1\/status-pages\/([0-9a-f-]{36})(?:\/(publish))?$/i);
    if (statusPageMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
      const pageId = statusPageMatch[1];
      const action = statusPageMatch[2];
      const page = await env.DB.prepare(`SELECT id, organization_id AS organizationId, name, slug, description,
          is_published AS isPublished, published_at AS publishedAt, archived_at AS archivedAt
        FROM status_pages WHERE id = ? AND archived_at IS NULL`)
        .bind(pageId)
        .first<{
          id: string; organizationId: string; name: string; slug: string; description: string;
          isPublished: number; publishedAt: string | null; archivedAt: string | null;
        }>();
      if (!page) return json({ error: "NOT_FOUND" }, 404);
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(page.organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);

      if (request.method === "GET" && !action) {
        const components = await env.DB.prepare(`SELECT m.id, m.name, m.monitor_type AS monitorType
          FROM status_page_monitors spm
          JOIN monitors m ON m.id = spm.monitor_id
          WHERE spm.page_id = ? AND m.deleted_at IS NULL
          ORDER BY spm.position ASC, m.name ASC`)
          .bind(pageId).all();
        return json({ statusPage: page, components: components.results });
      }

      if (request.method === "PATCH" && !action) {
        if (!["owner", "admin"].includes(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "status-page-update", 30))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const name = body?.name === undefined ? page.name : cleanText(body.name, 80);
        const description = body?.description === undefined ? page.description : (typeof body.description === "string" ? body.description.trim() : "");
        const slug = body?.slug === undefined ? page.slug : cleanText(body.slug, 48).toLowerCase();
        const slugPattern = /^[a-z0-9](?:[a-z0-9-]{1,46}[a-z0-9])$/;
        const reservedSlugs = new Set(["admin", "api", "app", "auth", "health", "status", "status-pages"]);
        const hasMonitorIds = body?.monitorIds !== undefined;
        const monitorIds = hasMonitorIds && Array.isArray(body.monitorIds) ? body.monitorIds : [];
        if (name.length < 2 || /[\u0000-\u001f\u007f]/.test(name) || description.length > 240 ||
            /[\u0000-\u001f\u007f]/.test(description) ||
            !slugPattern.test(slug) || reservedSlugs.has(slug) ||
            (hasMonitorIds && (!Array.isArray(body?.monitorIds) || monitorIds.length > 50 ||
              monitorIds.some(value => typeof value !== "string" || !/^[0-9a-f-]{36}$/i.test(value)) ||
              new Set(monitorIds).size !== monitorIds.length))) {
          return json({ error: "INVALID_STATUS_PAGE_INPUT" }, 400);
        }
        if (hasMonitorIds && monitorIds.length) {
          const placeholders = monitorIds.map(() => "?").join(",");
          const valid = await env.DB.prepare(`SELECT COUNT(*) AS count FROM monitors
            WHERE organization_id = ? AND deleted_at IS NULL AND id IN (${placeholders})`)
            .bind(page.organizationId, ...monitorIds).first<{ count: number }>();
          if ((valid?.count ?? 0) !== monitorIds.length) return json({ error: "INVALID_STATUS_PAGE_MONITORS" }, 400);
        }
        if (hasMonitorIds && monitorIds.length === 0 && Number(page.isPublished) === 1) {
          return json({ error: "STATUS_PAGE_REQUIRES_COMPONENT" }, 409);
        }
        const statements = [
          env.DB.prepare("UPDATE status_pages SET name = ?, slug = ?, description = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND archived_at IS NULL")
            .bind(name, slug, description, pageId, page.organizationId)
        ];
        if (hasMonitorIds) {
          statements.push(env.DB.prepare("DELETE FROM status_page_monitors WHERE page_id = ?").bind(pageId));
          for (let position = 0; position < monitorIds.length; position++) {
            statements.push(env.DB.prepare("INSERT INTO status_page_monitors (page_id, monitor_id, position) VALUES (?, ?, ?)")
              .bind(pageId, monitorIds[position], position));
          }
        }
        statements.push(env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) VALUES (?, ?, ?, 'status_page.updated', 'status_page', ?, ?)")
          .bind(id(), page.organizationId, user.id, pageId, JSON.stringify({ slug, componentsChanged: hasMonitorIds })));
        try {
          await env.DB.batch(statements);
        } catch {
          return json({ error: "STATUS_PAGE_UPDATE_CONFLICT" }, 409);
        }
        return json({ message: "Status page updated.", statusPage: { id: pageId, name, slug, description } });
      }

      if (request.method === "POST" && action === "publish") {
        if (!["owner", "admin"].includes(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "status-page-publish", 20))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        if (typeof body?.published !== "boolean") return json({ error: "INVALID_PUBLISH_STATE" }, 400);
        if (body.published) {
          const count = await env.DB.prepare(`SELECT COUNT(*) AS count
            FROM status_page_monitors spm JOIN monitors m ON m.id = spm.monitor_id
            WHERE spm.page_id = ? AND m.deleted_at IS NULL`)
            .bind(pageId).first<{ count: number }>();
          if ((count?.count ?? 0) < 1) return json({ error: "STATUS_PAGE_REQUIRES_COMPONENT" }, 409);
        }
        const publishAction = body.published ? "status_page.published" : "status_page.unpublished";
        const result = await env.DB.batch([
          env.DB.prepare("UPDATE status_pages SET is_published = ?, published_at = CASE WHEN ? = 1 THEN COALESCE(published_at, CURRENT_TIMESTAMP) ELSE NULL END, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND archived_at IS NULL AND is_published != ?")
            .bind(body.published ? 1 : 0, body.published ? 1 : 0, pageId, page.organizationId, body.published ? 1 : 0),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, ?, 'status_page', ? WHERE changes() = 1")
            .bind(id(), page.organizationId, user.id, publishAction, pageId)
        ]);
        return json({ message: body.published ? "Status page published." : "Status page unpublished.", changed: (result[0]?.meta?.changes ?? 0) === 1 });
      }

      if (request.method === "DELETE" && !action) {
        if (!["owner", "admin"].includes(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "status-page-archive", 20))) return json({ error: "RATE_LIMITED" }, 429);
        const result = await env.DB.batch([
          env.DB.prepare("UPDATE status_pages SET is_published = 0, published_at = NULL, archived_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND archived_at IS NULL")
            .bind(pageId, page.organizationId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'status_page.archived', 'status_page', ? WHERE changes() = 1")
            .bind(id(), page.organizationId, user.id, pageId)
        ]);
        return json({ message: "Status page archived.", changed: (result[0]?.meta?.changes ?? 0) === 1 });
      }
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }

    // Email notification channels are bound to the signed-in user's own verified address.
    const notificationChannelsCollectionMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/notification-channels$/i);
    const notificationChannelItemMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/notification-channels\/([0-9a-f-]{36})$/i);
    const notificationDeliveriesMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/notification-deliveries$/i);
    if (notificationChannelsCollectionMatch || notificationChannelItemMatch || notificationDeliveriesMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
      const organizationId = (notificationChannelsCollectionMatch || notificationChannelItemMatch || notificationDeliveriesMatch)![1];
      const channelId = notificationChannelItemMatch?.[2];
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);
      const canManageAllChannels = membership.role === "owner" || membership.role === "admin";

      if (notificationChannelsCollectionMatch && request.method === "GET") {
        const rows = await env.DB.prepare(`
          SELECT id, channel_type AS channelType, destination,
            is_enabled AS isEnabled, created_by AS createdBy,
            verified_at AS verifiedAt, created_at AS createdAt
          FROM notification_channels
          WHERE organization_id = ? AND (? = 1 OR created_by = ?)
          ORDER BY created_at DESC, id ASC
          LIMIT 50
        `).bind(organizationId, canManageAllChannels ? 1 : 0, user.id).all();
        return json({ channels: rows.results });
      }

      if (notificationChannelsCollectionMatch && request.method === "POST") {
        if (!canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "notification-channel-create", 10))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const channelType = cleanText(body?.channelType, 16) || "email";
        const suppliedEmail = body?.email === undefined ? user.email : cleanText(body.email, 254).toLowerCase();
        if (channelType !== "email") return json({ error: "WEBHOOK_CHANNEL_NOT_AVAILABLE", message: "Webhook delivery will be enabled after the SSRF-safe outbound transport is complete." }, 409);
        if (!emailPattern.test(user.email) || suppliedEmail.toLowerCase() !== user.email.toLowerCase() || !user.email_verified_at) {
          return json({ error: "EMAIL_MUST_MATCH_VERIFIED_ACCOUNT" }, 400);
        }
        const newChannelId = id();
        const verifiedAt = new Date().toISOString();
        try {
          await env.DB.batch([
            env.DB.prepare("INSERT INTO notification_channels (id, organization_id, channel_type, destination, is_enabled, created_by, verified_at, updated_at) VALUES (?, ?, 'email', ?, 1, ?, ?, ?)")
              .bind(newChannelId, organizationId, user.email, user.id, verifiedAt, verifiedAt),
            env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) VALUES (?, ?, ?, 'notification.email_channel_created', 'notification_channel', ?, ?)")
              .bind(id(), organizationId, user.id, newChannelId, JSON.stringify({ channelType: "email" }))
          ]);
        } catch {
          return json({ error: "EMAIL_CHANNEL_ALREADY_EXISTS" }, 409);
        }
        return json({ message: "Verified email alert channel added.", channel: {
          id: newChannelId, channelType: "email", destination: user.email,
          isEnabled: true, verifiedAt, createdAt: verifiedAt
        } }, 201);
      }

      if (notificationDeliveriesMatch && request.method === "GET") {
        const rows = await env.DB.prepare(`
          SELECT d.id, d.event_type AS eventType, d.recipient_email AS recipientEmail,
            d.status, d.attempt_count AS attemptCount, d.last_error_code AS lastErrorCode,
            d.created_at AS createdAt, d.delivered_at AS deliveredAt,
            d.next_attempt_at AS nextAttemptAt, m.name AS monitorName
          FROM notification_deliveries d
          LEFT JOIN incidents i ON i.id = d.incident_id
          LEFT JOIN monitors m ON m.id = i.monitor_id
          WHERE d.organization_id = ? AND (? = 1 OR d.channel_created_by = ?)
          ORDER BY d.created_at DESC, d.id DESC
          LIMIT 100
        `).bind(organizationId, canManageAllChannels ? 1 : 0, user.id).all();
        return json({ deliveries: rows.results });
      }

      if (notificationChannelItemMatch && channelId && (request.method === "PATCH" || request.method === "DELETE")) {
        if (!(await rateLimit(request, env, "notification-channel-update", 30))) return json({ error: "RATE_LIMITED" }, 429);
        const channel = await env.DB.prepare("SELECT id, created_by AS createdBy, is_enabled AS isEnabled FROM notification_channels WHERE id = ? AND organization_id = ? AND channel_type = 'email'")
          .bind(channelId, organizationId).first<{ id: string; createdBy: string | null; isEnabled: number }>();
        if (!channel) return json({ error: "NOT_FOUND" }, 404);
        if (!canManageAllChannels && channel.createdBy !== user.id) return json({ error: "FORBIDDEN" }, 403);

        if (request.method === "PATCH") {
          const body = await request.json().catch(() => null) as Record<string, unknown> | null;
          if (typeof body?.enabled !== "boolean") return json({ error: "INVALID_CHANNEL_STATE" }, 400);
          const enabled = body.enabled ? 1 : 0;
          const now = new Date().toISOString();
          const results = await env.DB.batch([
            env.DB.prepare("UPDATE notification_channels SET is_enabled = ?, updated_at = ? WHERE id = ? AND organization_id = ? AND is_enabled <> ?")
              .bind(enabled, now, channelId, organizationId, enabled),
            env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) SELECT ?, ?, ?, ?, 'notification_channel', ?, ? WHERE changes() = 1")
              .bind(id(), organizationId, user.id, enabled ? "notification.email_channel_enabled" : "notification.email_channel_disabled", channelId, JSON.stringify({ enabled: Boolean(enabled) })),
            env.DB.prepare("UPDATE notification_deliveries SET status = 'failed', next_attempt_at = NULL, last_error_code = 'CHANNEL_DISABLED', lease_token = NULL, lease_until = NULL, updated_at = ? WHERE channel_id = ? AND status = 'queued' AND ? = 0")
              .bind(now, channelId, enabled)
          ]);
          return json({ message: enabled ? "Email alerts enabled." : "Email alerts disabled.", changed: (results[0]?.meta?.changes ?? 0) === 1 });
        }

        const now = new Date().toISOString();
        await env.DB.batch([
          env.DB.prepare("UPDATE notification_deliveries SET status = 'failed', next_attempt_at = NULL, last_error_code = 'CHANNEL_REMOVED', lease_token = NULL, lease_until = NULL, updated_at = ? WHERE channel_id = ? AND status = 'queued'")
            .bind(now, channelId),
          env.DB.prepare("DELETE FROM notification_channels WHERE id = ? AND organization_id = ?")
            .bind(channelId, organizationId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'notification.email_channel_removed', 'notification_channel', ? WHERE changes() = 1")
            .bind(id(), organizationId, user.id, channelId)
        ]);
        return json({ message: "Email alert channel removed. Pending deliveries were cancelled." });
      }
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }

    // Team management: all routes are scoped through a verified organization membership.
    const teamMatch = url.pathname.match(/^\/v1\/organizations\/([0-9a-f-]{36})\/(members|invitations)(?:\/([0-9a-f-]{36}))?$/i);
    if (teamMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
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
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
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
      if (!apiKeyAllows(user, organizationId, "read")) return json({ error: "FORBIDDEN" }, 403);
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);
      const executionEnabled = isProbeExecutionEnabled(env);
      const result = await env.DB.prepare(`SELECT m.id, m.name, m.monitor_type, m.target_url, m.method, m.expected_status,
        m.interval_seconds, m.timeout_ms, m.is_enabled, m.consecutive_failures, m.last_checked_at, m.next_check_at, m.created_at, m.updated_at,
        (SELECT c.is_up FROM monitor_checks c WHERE c.monitor_id = m.id ORDER BY c.checked_at DESC, c.id DESC LIMIT 1) AS last_check_is_up,
        (SELECT i.status FROM incidents i WHERE i.monitor_id = m.id AND i.resolved_at IS NULL ORDER BY i.started_at DESC, i.id DESC LIMIT 1) AS open_incident_status
        FROM monitors m WHERE m.organization_id = ? AND m.deleted_at IS NULL ORDER BY m.created_at DESC LIMIT 100`).bind(organizationId).all();
      const monitors = result.results.map(row => ({
        ...row,
        state: getMonitorState(row as MonitorStateRow, executionEnabled)
      }));
      return json({
        monitors,
        executionEnabled,
        ...(executionEnabled ? {} : { note: "Scheduled probes are disabled; monitors are saved but have not been probed." })
      });
    }

    if (request.method === "POST" && url.pathname === "/v1/monitors") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      if (user.authMethod === "api_key") return json({ error: "FORBIDDEN" }, 403);
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
      const executionEnabled = isProbeExecutionEnabled(env);
      return json({
        monitor: {
          id: monitorId, organizationId, name, monitorType, targetUrl: target, method, expectedStatus,
          intervalSeconds, timeoutMs, state: executionEnabled ? "awaiting_first_check" : "execution_disabled"
        },
        executionEnabled,
        ...(executionEnabled ? {} : { note: "Scheduled probes are disabled; the target has not been contacted." })
      }, 201);
    }

    const monitorMatch = url.pathname.match(/^\/v1\/monitors\/([0-9a-f-]{36})(\/checks|\/pause|\/resume)?$/i);
    if (monitorMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const monitorId = monitorMatch[1];
      const monitor = await env.DB.prepare(`SELECT m.id, m.organization_id, m.name, m.target_url, m.monitor_type, m.method,
        m.expected_status, m.interval_seconds, m.timeout_ms, m.is_enabled, m.last_checked_at, m.next_check_at,
        m.consecutive_failures,
        (SELECT c.is_up FROM monitor_checks c WHERE c.monitor_id = m.id ORDER BY c.checked_at DESC, c.id DESC LIMIT 1) AS last_check_is_up,
        (SELECT i.status FROM incidents i WHERE i.monitor_id = m.id AND i.resolved_at IS NULL ORDER BY i.started_at DESC, i.id DESC LIMIT 1) AS open_incident_status
        FROM monitors m WHERE m.id = ? AND m.deleted_at IS NULL`)
        .bind(monitorId).first<{
          id: string; organization_id: string; name: string; target_url: string; monitor_type: string;
          method: string; expected_status: number; interval_seconds: number; timeout_ms: number;
          is_enabled: number; last_checked_at: string | null; next_check_at: string | null;
          consecutive_failures: number; last_check_is_up: number | null; open_incident_status: string | null;
        }>();
      if (!monitor) return json({ error: "NOT_FOUND" }, 404);
      if (!apiKeyAllows(user, monitor.organization_id, "read")) return json({ error: "FORBIDDEN" }, 403);
      const membership = await env.DB.prepare("SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?")
        .bind(monitor.organization_id, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);
      if (user.authMethod === "api_key" && request.method !== "GET") return json({ error: "FORBIDDEN" }, 403);

      if (monitorMatch[2] === "/pause" || monitorMatch[2] === "/resume") {
        if (request.method !== "POST") return json({ error: "METHOD_NOT_ALLOWED" }, 405);
        if (!canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "monitor-control", 30))) return json({ error: "RATE_LIMITED" }, 429);

        const enable = monitorMatch[2] === "/resume" ? 1 : 0;
        const updateSql = enable === 1
          ? "UPDATE monitors SET is_enabled = 1, next_check_at = CURRENT_TIMESTAMP, check_lease_token = NULL, check_lease_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND deleted_at IS NULL AND is_enabled = 0"
          : "UPDATE monitors SET is_enabled = 0, check_lease_token = NULL, check_lease_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND deleted_at IS NULL AND is_enabled = 1";
        const auditAction = enable === 1 ? "monitor.resumed" : "monitor.paused";
        const results = await env.DB.batch([
          env.DB.prepare(updateSql).bind(monitorId, monitor.organization_id),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, ?, 'monitor', ? WHERE changes() = 1")
            .bind(id(), monitor.organization_id, user.id, auditAction, monitorId),
          env.DB.prepare("SELECT is_enabled FROM monitors WHERE id = ? AND organization_id = ? AND deleted_at IS NULL")
            .bind(monitorId, monitor.organization_id)
        ]);
        const current = results[2]?.results?.[0] as { is_enabled: number } | undefined;
        if (!current) return json({ error: "NOT_FOUND" }, 404);
        const changed = (results[0]?.meta?.changes ?? 0) === 1;
        const isEnabled = Number(current.is_enabled) === 1;
        const executionEnabled = isProbeExecutionEnabled(env);
        return json({
          message: isEnabled ? "Monitor resumed." : "Monitor paused.",
          changed,
          monitor: { id: monitorId, isEnabled },
          executionEnabled,
          note: executionEnabled
            ? "The scheduler will honor this enabled/paused state on its next pass."
            : "Probe execution is disabled; this action only changes the saved monitor state."
        });
      }

      if (request.method === "GET" && monitorMatch[2] === "/checks") {
        const checks = await env.DB.prepare(`SELECT id, checked_at, is_up, status_code, response_time_ms, error_code
          FROM monitor_checks WHERE monitor_id = ? ORDER BY checked_at DESC LIMIT 100`).bind(monitorId).all();
        const executionEnabled = isProbeExecutionEnabled(env);
        return json({
          checks: checks.results,
          executionEnabled,
          ...(executionEnabled ? {} : { note: "Scheduled probes are disabled; no new checks are being recorded." })
        });
      }
      if (request.method === "GET") {
        const executionEnabled = isProbeExecutionEnabled(env);
        const state = getMonitorState(monitor, executionEnabled);
        return json({
          monitor: { ...monitor, state },
          state,
          executionEnabled,
          ...(executionEnabled ? {} : { note: "Scheduled probes are disabled; this view only reads stored monitoring records." })
        });
      }
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
            interval_seconds = ?, timeout_ms = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND deleted_at IS NULL`)
            .bind(name, target, method, expectedStatus, intervalSeconds, timeoutMs, monitorId, monitor.organization_id),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) VALUES (?, ?, ?, 'monitor.updated', 'monitor', ?)")
            .bind(id(), monitor.organization_id, user.id, monitorId)
        ]);
        return json({ message: "Monitor updated.", executionEnabled: isProbeExecutionEnabled(env) });
      }
      if (request.method === "DELETE") {
        if (!canDeleteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        const deletedAt = new Date().toISOString();
        const results = await env.DB.batch([
          env.DB.prepare("UPDATE monitors SET is_enabled = 0, deleted_at = ?, deleted_by = ?, check_lease_token = NULL, check_lease_until = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND organization_id = ? AND deleted_at IS NULL")
            .bind(deletedAt, user.id, monitorId, monitor.organization_id),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id) SELECT ?, ?, ?, 'monitor.deleted', 'monitor', ? WHERE changes() = 1")
            .bind(id(), monitor.organization_id, user.id, monitorId)
        ]);
        // SQLite/D1 may include trigger side-effects in batch metadata. The status-page trigger can also unpublish a page, so a successful monitor update may report more than one changed row.
        if (((results[0] as D1Result).meta?.changes ?? 0) < 1) return json({ error: "MONITOR_ALREADY_DELETED" }, 409);
        return json({ message: "Monitor deleted. Check history and incident timelines are retained." });
      }
      return json({ error: "METHOD_NOT_ALLOWED" }, 405);
    }

    if (request.method === "GET" && url.pathname === "/v1/incidents") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const organizationId = cleanText(url.searchParams.get("organizationId"), 64);
      if (!organizationId) return json({ error: "ORGANIZATION_REQUIRED" }, 400);
      if (!apiKeyAllows(user, organizationId, "read")) return json({ error: "FORBIDDEN" }, 403);
      const membership = await env.DB.prepare(
        "SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?"
      ).bind(organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);

      const result = await env.DB.prepare(`SELECT
          i.id,
          i.monitor_id AS monitorId,
          m.name AS monitorName,
          m.target_url AS targetUrl,
          i.started_at AS startedAt,
          i.resolved_at AS resolvedAt,
          i.status,
          i.summary,
          i.created_at AS createdAt
        FROM incidents i
        JOIN monitors m ON m.id = i.monitor_id
        WHERE m.organization_id = ?
        ORDER BY i.started_at DESC, i.id DESC
        LIMIT 100`)
        .bind(organizationId)
        .all();
      return json({ incidents: result.results });
    }

    const incidentMatch = url.pathname.match(/^\/v1\/incidents\/([0-9a-f-]{36})(?:\/(updates))?$/i);
    if (incidentMatch) {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "UNAUTHENTICATED" }, 401);
      const incidentId = incidentMatch[1];
      const incident = await env.DB.prepare(`SELECT
          i.id,
          i.monitor_id AS monitorId,
          m.organization_id AS organizationId,
          m.name AS monitorName,
          m.target_url AS targetUrl,
          i.started_at AS startedAt,
          i.resolved_at AS resolvedAt,
          i.status,
          i.summary,
          i.created_at AS createdAt
        FROM incidents i
        JOIN monitors m ON m.id = i.monitor_id
        WHERE i.id = ?`)
        .bind(incidentId)
        .first<{
          id: string;
          monitorId: string;
          organizationId: string;
          monitorName: string;
          targetUrl: string;
          startedAt: string;
          resolvedAt: string | null;
          status: string;
          summary: string;
          createdAt: string;
        }>();
      if (!incident) return json({ error: "NOT_FOUND" }, 404);
      if (!apiKeyAllows(user, incident.organizationId, "read")) return json({ error: "FORBIDDEN" }, 403);

      const membership = await env.DB.prepare(
        "SELECT role FROM organization_members WHERE organization_id = ? AND user_id = ?"
      ).bind(incident.organizationId, user.id).first<{ role: string }>();
      if (!membership) return json({ error: "FORBIDDEN" }, 403);
      if (user.authMethod === "api_key" && request.method !== "GET") return json({ error: "FORBIDDEN" }, 403);

      const isUpdatesRoute = incidentMatch[2] === "updates";

      if (request.method === "PATCH" && !isUpdatesRoute) {
        if (!canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "incident-status", 30))) return json({ error: "RATE_LIMITED" }, 429);
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const nextStatus = cleanText(body?.status, 24);
        const transitions: Record<string, readonly string[]> = {
          investigating: ["identified"],
          identified: ["investigating", "monitoring"],
          monitoring: ["identified", "resolved"]
        };
        if (!transitions[incident.status]?.includes(nextStatus)) {
          return json({ error: "INVALID_INCIDENT_TRANSITION" }, 409);
        }
        const suppliedMessage = body?.message === undefined
          ? ""
          : typeof body.message === "string" ? body.message.replace(/\r\n?/g, "\n").trim() : "";
        if (body?.message !== undefined &&
            (!suppliedMessage || suppliedMessage.length > 500 ||
             /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(suppliedMessage))) {
          return json({ error: "INVALID_INCIDENT_MESSAGE" }, 400);
        }
        const visibility = body?.visibility === undefined ? "internal" : cleanText(body.visibility, 16);
        if (visibility !== "internal" && visibility !== "public") {
          return json({ error: "INVALID_INCIDENT_VISIBILITY" }, 400);
        }
        const message = suppliedMessage || ("Status changed from " + incident.status + " to " + nextStatus + ".");
        const changedAt = new Date().toISOString();
        const statusEventId = id();
        const results = await env.DB.batch([
          env.DB.prepare("UPDATE incidents SET status = ?, resolved_at = CASE WHEN ? = 'resolved' THEN ? ELSE NULL END WHERE id = ? AND status = ? AND resolved_at IS NULL")
            .bind(nextStatus, nextStatus, changedAt, incidentId, incident.status),
          env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at, actor_user_id, visibility) SELECT ?, ?, 'incident.status_changed', ?, ?, ?, ? WHERE changes() = 1")
            .bind(statusEventId, incidentId, message, changedAt, user.id, visibility),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) SELECT ?, ?, ?, 'incident.status_changed', 'incident', ?, ? WHERE changes() = 1")
            .bind(id(), incident.organizationId, user.id, incidentId, JSON.stringify({
              from: incident.status, to: nextStatus, visibility
            })),
          enqueueNotificationDeliveries(env, statusEventId, "incident.status_changed", changedAt)
        ]);
        if ((results[0] as D1Result).meta?.changes !== 1) {
          return json({ error: "INCIDENT_CHANGED" }, 409);
        }
        return json({ message: "Incident status updated.", status: nextStatus });
      }

      if (request.method === "POST" && isUpdatesRoute) {
        if (!canWriteMonitors(membership.role)) return json({ error: "FORBIDDEN" }, 403);
        if (!(await rateLimit(request, env, "incident-update", 30))) return json({ error: "RATE_LIMITED" }, 429);
        if (incident.resolvedAt || incident.status === "resolved") {
          return json({ error: "INCIDENT_ALREADY_RESOLVED" }, 409);
        }
        const body = await request.json().catch(() => null) as Record<string, unknown> | null;
        const message = typeof body?.message === "string"
          ? body.message.replace(/\r\n?/g, "\n").trim()
          : "";
        if (!message || message.length > 500 ||
            /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/.test(message)) {
          return json({ error: "INVALID_INCIDENT_MESSAGE" }, 400);
        }
        const visibility = body?.visibility === undefined ? "internal" : cleanText(body.visibility, 16);
        if (visibility !== "internal" && visibility !== "public") {
          return json({ error: "INVALID_INCIDENT_VISIBILITY" }, 400);
        }
        const createdAt = new Date().toISOString();
        const eventId = id();
        const results = await env.DB.batch([
          env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at, actor_user_id, visibility) SELECT ?, ?, 'incident.update', ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM incidents WHERE id = ? AND resolved_at IS NULL)")
            .bind(eventId, incidentId, message, createdAt, user.id, visibility, incidentId),
          env.DB.prepare("INSERT INTO audit_logs (id, organization_id, actor_user_id, action, resource_type, resource_id, metadata_json) SELECT ?, ?, ?, 'incident.update_added', 'incident', ?, ? WHERE changes() = 1")
            .bind(id(), incident.organizationId, user.id, incidentId, JSON.stringify({ visibility })),
            enqueueNotificationDeliveries(env, eventId, "incident.update", createdAt)
        ]);
        if ((results[0] as D1Result).meta?.changes !== 1) {
          return json({ error: "INCIDENT_ALREADY_RESOLVED" }, 409);
        }
        return json({ message: "Incident update added.", eventId, visibility }, 201);
      }

      if (request.method === "GET" && !isUpdatesRoute) {
        const events = await env.DB.prepare("SELECT e.id, e.event_type AS eventType, e.message, e.created_at AS createdAt, e.visibility, e.actor_user_id AS actorUserId, u.display_name AS actorName FROM incident_events e LEFT JOIN users u ON u.id = e.actor_user_id WHERE e.incident_id = ? AND (? = 0 OR e.visibility = ?) ORDER BY e.created_at ASC, e.id ASC")
          .bind(incidentId, user.authMethod === "api_key" ? 1 : 0, "public")
          .all();
        return json({ incident, events: events.results });
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
      headers.set("access-control-allow-headers", "Content-Type, Authorization");
      headers.append("vary", "Origin");
    }
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  },
  async scheduled(controller: ScheduledController, env: Env, _ctx: ExecutionContext): Promise<void> {
    if (controller.cron !== "*/1 * * * *") return;
    const startedAt = new Date();
    const schedulerLagMs = Math.max(0, startedAt.getTime() - controller.scheduledTime);

    // Run bounded email delivery before probes so the two batches do not
    // compete for Cloudflare's simultaneous outbound-connection slots.
    try {
      const notifications = await dispatchNotificationBatch(env, { now: startedAt, limit: 5 });
      if (notifications.skipped) {
        console.info("notification_dispatch_skipped", { reason: "NOTIFICATION_CONFIGURATION_MISSING", schedulerLagMs });
      } else if (notifications.claimed > 0) {
        console.info("notification_dispatch_completed", { ...notifications, schedulerLagMs });
      }
    } catch {
      console.error("notification_dispatch_failed", { schedulerLagMs });
    }

    try {
      const probes = await dispatchDueMonitors(env);
      if (probes.skipped) {
        console.info("monitor_dispatch_skipped", { reason: probes.reason, schedulerLagMs });
      } else {
        console.info("monitor_dispatch_completed", {
          claimed: probes.claimed, finalized: probes.finalized, deferred: probes.deferred,
          stale: probes.stale, dispatchErrors: probes.dispatchErrors, schedulerLagMs
        });
      }
    } catch {
      console.error("monitor_dispatch_failed", { schedulerLagMs });
    }
  }
};
