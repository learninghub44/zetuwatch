import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { signProbePayload } from "../packages/probe-client/src/client.mjs";

const secret = (env as typeof env & { PROBE_SHARED_SECRET: string }).PROBE_SHARED_SECRET;
const encoder = new TextEncoder();
const makeNonce = () => crypto.randomUUID().replaceAll("-", "");

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function makeRequest(options: {
  nonce: string;
  timestamp?: string;
  rawBody?: string;
  signature?: string;
  origin?: string;
  ip?: string;
}): Promise<Response> {
  const timestamp = options.timestamp ?? String(Math.floor(Date.now() / 1000));
  const rawBody = options.rawBody ?? JSON.stringify({ nonce: options.nonce });
  return (async () => {
    const signature = options.signature ?? await signProbePayload(secret, timestamp, options.nonce, rawBody);
    const headers = new Headers({
      "content-type": "application/json",
      "cf-connecting-ip": options.ip ?? "198.51.100.77",
      "x-zw-timestamp": timestamp,
      "x-zw-nonce": options.nonce,
      "x-zw-signature": signature
    });
    if (options.origin) headers.set("origin", options.origin);
    return exports.default.fetch(new Request("https://api.zetuwatch.test/internal/probe-agent/replay", {
      method: "POST", headers, body: rawBody
    }));
  })();
}

describe("D1-backed probe-agent replay guard", () => {
  it("atomically accepts one nonce and rejects concurrent duplicates", async () => {
    const nonce = makeNonce();
    const [first, second] = await Promise.all([
      makeRequest({ nonce, ip: "198.51.100.78" }),
      makeRequest({ nonce, ip: "198.51.100.78" })
    ]);
    expect([first.status, second.status].sort()).toEqual([204, 409]);

    const nonceHash = await sha256(nonce);
    const row = await env.DB.prepare(
      "SELECT nonce_hash AS nonceHash FROM probe_agent_replay_nonces WHERE nonce_hash = ?"
    ).bind(nonceHash).first<{ nonceHash: string }>();
    expect(row?.nonceHash).toBe(nonceHash);
    expect(row?.nonceHash).not.toBe(nonce);
  });

  it("verifies the exact raw body, header/body nonce binding and timestamp window", async () => {
    const nonce = makeNonce();
    const compact = JSON.stringify({ nonce });
    const spaced = "{ \"nonce\": \"" + nonce + "\" }";
    const signature = await signProbePayload(secret, String(Math.floor(Date.now() / 1000)), nonce, compact);
    const invalidSignatureIp = "198.51.100.79";
    const rateKey = await sha256("probe-agent-replay:" + invalidSignatureIp);
    const beforeRateLimit = await env.DB.prepare(
      "SELECT attempts FROM auth_rate_limits WHERE key_hash = ?"
    ).bind(rateKey).first<{ attempts: number }>();
    const tampered = await makeRequest({ nonce, rawBody: spaced, signature, ip: invalidSignatureIp });
    expect(tampered.status).toBe(401);
    const afterRateLimit = await env.DB.prepare(
      "SELECT attempts FROM auth_rate_limits WHERE key_hash = ?"
    ).bind(rateKey).first<{ attempts: number }>();
    expect(afterRateLimit?.attempts ?? 0).toBe(beforeRateLimit?.attempts ?? 0);

    const otherNonce = makeNonce();
    const mismatch = await makeRequest({
      nonce: otherNonce,
      rawBody: JSON.stringify({ nonce }),
      ip: "198.51.100.80"
    });
    expect(mismatch.status).toBe(401);

    const staleTimestamp = String(Math.floor(Date.now() / 1000) - 120);
    const stale = await makeRequest({ nonce: makeNonce(), timestamp: staleTimestamp, ip: "198.51.100.81" });
    expect(stale.status).toBe(401);
  });

  it("removes expired hashes before claiming a fresh request", async () => {
    const nonce = makeNonce();
    const nonceHash = await sha256(nonce);
    const createdAt = new Date(Date.now() - 2_000).toISOString();
    const expiredAt = new Date(Date.now() - 1_000).toISOString();
    await env.DB.prepare(
      "INSERT INTO probe_agent_replay_nonces (nonce_hash, expires_at, created_at) VALUES (?, ?, ?)"
    ).bind(nonceHash, expiredAt, createdAt).run();

    const response = await makeRequest({ nonce, ip: "198.51.100.82" });
    expect(response.status).toBe(204);
    const row = await env.DB.prepare(
      "SELECT expires_at AS expiresAt FROM probe_agent_replay_nonces WHERE nonce_hash = ?"
    ).bind(nonceHash).first<{ expiresAt: string }>();
    expect(Date.parse(row!.expiresAt)).toBeGreaterThan(Date.now());
  });

  it("rejects browser origins and oversized bodies without writing a nonce", async () => {
    const nonce = makeNonce();
    const oversizedNonce = makeNonce();
    const browser = await makeRequest({ nonce, origin: "https://app.zetuwatch.test", ip: "198.51.100.83" });
    expect(browser.status).toBe(403);

    const hugeBody = JSON.stringify({ nonce: oversizedNonce, extra: "x".repeat(512) });
    const oversized = await makeRequest({
      nonce: oversizedNonce,
      rawBody: hugeBody,
      ip: "198.51.100.84"
    });
    expect(oversized.status).toBe(413);

    const count = await env.DB.prepare(
      "SELECT COUNT(*) AS total FROM probe_agent_replay_nonces WHERE nonce_hash IN (?, ?)"
    ).bind(await sha256(nonce), await sha256(oversizedNonce))
      .first<{ total: number }>();
    expect(count?.total).toBe(0);
  });
});
