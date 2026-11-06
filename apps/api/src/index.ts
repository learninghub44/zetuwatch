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

async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 310000 }, material, 256);
  return `pbkdf2_sha256$310000$${b64url(salt)}$${b64url(new Uint8Array(bits))}`;
}
async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 4 || parts[0] !== "pbkdf2_sha256" || parts[1] !== "310000") return false;
  try {
    const saltText = parts[2].replace(/-/g, "+").replace(/_/g, "/");
    const expectedText = parts[3].replace(/-/g, "+").replace(/_/g, "/");
    const salt = Uint8Array.from(atob(saltText + "=".repeat((4 - saltText.length % 4) % 4)), c => c.charCodeAt(0));
    const expected = Uint8Array.from(atob(expectedText + "=".repeat((4 - expectedText.length % 4) % 4)), c => c.charCodeAt(0));
    const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
    const actual = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 310000 }, material, 256));
    if (actual.length !== expected.length) return false;
    let diff = 0;
    for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
    return diff === 0;
  } catch { return false; }
}
async function sendEmail(env: Env, to: string, subject: string, html: string, key: string): Promise<boolean> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) return false;
  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { authorization: `Bearer ${env.RESEND_API_KEY}`, "content-type": "application/json", "Idempotency-Key": key, "User-Agent": "ZetuWatch/0.1" },
    body: JSON.stringify({ from: env.EMAIL_FROM, to: [to], subject, html })
  });
  return response.ok;
}
function cookie(name: string, value: string, maxAge: number, secure: boolean): string {
  return `${name}=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}
function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") || "";
  const match = header.split(";").map(v => v.trim()).find(v => v.startsWith(name + "="));
  return match ? decodeURIComponent(match.slice(name.length + 1)) : null;
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
      const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first<{ id: string }>();
      if (existing) return json({ error: "REGISTRATION_UNAVAILABLE", message: "If this address can be registered, a verification message will be sent." }, 202);
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
      const verifyUrl = `${env.PUBLIC_APP_URL.replace(/\/$/, "")}/verify-email?token=${encodeURIComponent(token)}`;
      const sent = await sendEmail(env, email, "Verify your ZetuWatch email", `<p>Hi ${htmlEscape(name)},</p><p>Confirm your email address to activate your ZetuWatch account.</p><p><a href="${verifyUrl}">Verify email address</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p>`, `verify-${userId}`);
      if (!sent) return json({ error: "VERIFICATION_EMAIL_FAILED", message: "Your account was created but the verification email could not be sent. Contact support to continue." }, 503);
      return json({ message: "Account created. Check your email to verify your address." }, 201);
    }

    if (request.method === "POST" && url.pathname === "/auth/verify") {
      if (!(await rateLimit(request, env, "verify", 10))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const token = cleanText(body?.token, 128);
      if (token.length < 32) return json({ error: "INVALID_OR_EXPIRED_TOKEN" }, 400);
      const tokenHash = await sha256(token);
      const row = await env.DB.prepare(`SELECT id, user_id FROM auth_tokens WHERE token_hash = ? AND purpose = 'verify_email'
        AND consumed_at IS NULL AND expires_at > ?`).bind(tokenHash, new Date().toISOString()).first<{ id: string; user_id: string }>();
      if (!row) return json({ error: "INVALID_OR_EXPIRED_TOKEN" }, 400);
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET email_verified_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE id = ?").bind(row.user_id),
        env.DB.prepare("UPDATE auth_tokens SET consumed_at = CURRENT_TIMESTAMP WHERE id = ? AND consumed_at IS NULL").bind(row.id)
      ]);
      return json({ message: "Email verified. You can now sign in." });
    }

    if (request.method === "POST" && url.pathname === "/auth/login") {
      if (!(await rateLimit(request, env, "login", 10))) return json({ error: "RATE_LIMITED" }, 429);
      const body = await request.json().catch(() => null) as Record<string, unknown> | null;
      const email = cleanText(body?.email, 254).toLowerCase();
      const password = typeof body?.password === "string" ? body.password : "";
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
