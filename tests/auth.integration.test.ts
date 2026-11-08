import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";

type FetchCall = [input: RequestInfo | URL, init?: RequestInit];

function api(
  path: string,
  options: { token?: string; method?: string; body?: Record<string, unknown> } = {}
): Promise<Response> {
  const headers = new Headers({ "cf-connecting-ip": crypto.randomUUID() });
  if (options.token) headers.set("cookie", `zw_session=${options.token}`);
  if (options.body) headers.set("content-type", "application/json");

  return exports.default.fetch(new Request(`https://api.zetuwatch.test${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  }));
}

function tokenFromEmail(init: RequestInit | undefined, route: "auth.html" | "reset-password.html"): string {
  const payload = JSON.parse(String(init?.body)) as { html?: string };
  const match = route === "auth.html"
    ? payload.html?.match(/auth\.html\?token=([^&"]+)/)
    : payload.html?.match(/reset-password\.html\?token=([^&"]+)/);
  if (!match?.[1]) throw new Error(`Expected ${route} token in mocked email payload`);
  return decodeURIComponent(match[1]);
}

describe("Worker authentication lifecycle", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("registers, verifies, signs in, resets the password and revokes old sessions without sending real email", async () => {
    const fetchMock = vi.fn(async (..._args: FetchCall) => Response.json({ id: "test-email-id" }));
    vi.stubGlobal("fetch", fetchMock);

    const email = `auth-${crypto.randomUUID()}@example.test`;
    const oldPassword = "Old-strong-password-2026!";
    const newPassword = "New-strong-password-2026!";

    const registerResponse = await api("/auth/register", {
      method: "POST",
      body: {
        email,
        name: "Auth Integration User",
        password: oldPassword,
        workspaceName: "Auth Test Workspace"
      }
    });
    expect(registerResponse.status).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const firstCall = fetchMock.mock.calls[0];
    expect(String(firstCall?.[0])).toBe("https://api.resend.com/emails");
    const firstInit = firstCall?.[1];
    const firstHeaders = firstInit?.headers as Record<string, string>;
    expect(firstHeaders.authorization).toBe("Bearer test-only-resend-key");
    expect(firstHeaders["Idempotency-Key"]).toBeTruthy();
    const verificationToken = tokenFromEmail(firstInit, "auth.html");

    const unverifiedLogin = await api("/auth/login", {
      method: "POST",
      body: { email, password: oldPassword }
    });
    expect(unverifiedLogin.status).toBe(403);
    expect(await unverifiedLogin.json()).toMatchObject({ error: "EMAIL_NOT_VERIFIED" });

    const verifyResponse = await api("/auth/verify", {
      method: "POST",
      body: { token: verificationToken }
    });
    expect(verifyResponse.status).toBe(200);

    const replayedVerification = await api("/auth/verify", {
      method: "POST",
      body: { token: verificationToken }
    });
    expect(replayedVerification.status).toBe(400);

    const loginResponse = await api("/auth/login", {
      method: "POST",
      body: { email, password: oldPassword }
    });
    expect(loginResponse.status).toBe(200);
    const cookie = loginResponse.headers.get("set-cookie") ?? "";
    const sessionToken = cookie.match(/(?:^|;\\s*)zw_session=([^;]+)/)?.[1];
    expect(sessionToken).toBeTruthy();

    const meResponse = await api("/auth/me", { token: sessionToken });
    expect(meResponse.status).toBe(200);
    const profile = await meResponse.json() as {
      user: { email: string };
      organizations: Array<{ name: string; role: string }>;
    };
    expect(profile.user.email).toBe(email);
    expect(profile.organizations).toEqual([
      expect.objectContaining({ name: "Auth Test Workspace", role: "owner" })
    ]);

    const resetRequest = await api("/auth/password-reset/request", {
      method: "POST",
      body: { email }
    });
    expect(resetRequest.status).toBe(202);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    const resetCall = fetchMock.mock.calls[1];
    expect(String(resetCall?.[0])).toBe("https://api.resend.com/emails");
    const resetToken = tokenFromEmail(resetCall?.[1], "reset-password.html");

    const resetResponse = await api("/auth/password-reset/confirm", {
      method: "POST",
      body: { token: resetToken, password: newPassword }
    });
    expect(resetResponse.status).toBe(200);

    const replayedReset = await api("/auth/password-reset/confirm", {
      method: "POST",
      body: { token: resetToken, password: "Another-password-2026!" }
    });
    expect(replayedReset.status).toBe(400);

    const oldSessionResponse = await api("/auth/me", { token: sessionToken });
    expect(oldSessionResponse.status).toBe(401);

    const oldPasswordLogin = await api("/auth/login", {
      method: "POST",
      body: { email, password: oldPassword }
    });
    expect(oldPasswordLogin.status).toBe(401);

    const newPasswordLogin = await api("/auth/login", {
      method: "POST",
      body: { email, password: newPassword }
    });
    expect(newPasswordLogin.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });
});
