import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";
import { decryptWebhookValue } from "../packages/notifications-core/src/webhook-secrets";

type Role = "owner" | "admin" | "member" | "viewer";
interface Identity {
  userId: string;
  organizationId: string;
  sessionToken: string;
}

const encryptionKey = (env as typeof env & { WEBHOOK_ENCRYPTION_KEY: string }).WEBHOOK_ENCRYPTION_KEY;
const sha256 = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
};

async function createIdentity(role: Role = "owner"): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const sessionToken = Array.from(crypto.getRandomValues(new Uint8Array(32)), byte => byte.toString(16).padStart(2, "0")).join("");
  await env.DB.batch([
    env.DB.prepare("INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)")
      .bind(userId, `${userId}@example.test`, "Webhook test user"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Webhook workspace", `webhook-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)")
      .bind(organizationId, userId, role),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, await sha256(sessionToken), new Date(Date.now() + 3_600_000).toISOString())
  ]);
  return { userId, organizationId, sessionToken };
}

function api(
  path: string,
  identity: Identity,
  options: { method?: string; body?: Record<string, unknown>; apiKey?: string } = {}
): Promise<Response> {
  const headers = new Headers({ "cf-connecting-ip": crypto.randomUUID() });
  if (identity.sessionToken) headers.set("cookie", `zw_session=${identity.sessionToken}`);
  if (options.apiKey) headers.set("authorization", `Bearer ${options.apiKey}`);
  if (options.body) headers.set("content-type", "application/json");
  return exports.default.fetch(new Request(`https://api.zetuwatch.test${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  }));
}

async function createEndpoint(identity: Identity, suffix = crypto.randomUUID()): Promise<{ id: string; secret: string }> {
  const response = await api(`/v1/organizations/${identity.organizationId}/webhooks`, identity, {
    method: "POST",
    body: { name: "Incident receiver", url: `https://hooks.example.com/${suffix}` }
  });
  expect(response.status).toBe(201);
  const payload = await response.json() as { endpoint: { id: string }; secret: string; deliveryEnabled: boolean };
  expect(payload.deliveryEnabled).toBe(false);
  expect(payload.secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
  return { id: payload.endpoint.id, secret: payload.secret };
}

describe("encrypted webhook endpoint configuration", () => {
  it("stores URL and signing secret encrypted and reveals the secret only once", async () => {
    const owner = await createIdentity("owner");
    const created = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner, {
      method: "POST",
      body: { name: "Payments", url: "https://hooks.example.com/v1/events?token=private-value" }
    });
    expect(created.status).toBe(201);
    const payload = await created.json() as {
      endpoint: { id: string; destinationHost: string; secretLast4: string; isEnabled: number };
      secret: string;
      deliveryEnabled: boolean;
    };
    expect(payload).toMatchObject({
      endpoint: { destinationHost: "hooks.example.com", isEnabled: 0 },
      deliveryEnabled: false
    });
    expect(payload.endpoint.secretLast4).toBe(payload.secret.slice(-4));

    const stored = await env.DB.prepare(`SELECT destination_ciphertext, destination_nonce,
      secret_ciphertext, secret_nonce, encryption_key_version
      FROM webhook_endpoints WHERE id = ? AND organization_id = ?`)
      .bind(payload.endpoint.id, owner.organizationId)
      .first<{
        destination_ciphertext: string; destination_nonce: string;
        secret_ciphertext: string; secret_nonce: string; encryption_key_version: number;
      }>();
    expect(stored).not.toBeNull();
    expect(stored?.encryption_key_version).toBe(1);
    expect(stored?.destination_ciphertext).not.toContain("hooks.example.com");
    expect(stored?.destination_ciphertext).not.toContain("private-value");
    expect(stored?.secret_ciphertext).not.toContain(payload.secret);

    const urlContext = `zetuwatch:webhook:v1:${owner.organizationId}:${payload.endpoint.id}:url`;
    const secretContext = `zetuwatch:webhook:v1:${owner.organizationId}:${payload.endpoint.id}:secret`;
    await expect(decryptWebhookValue({
      ciphertext: stored!.destination_ciphertext, nonce: stored!.destination_nonce
    }, encryptionKey, urlContext)).resolves.toBe("https://hooks.example.com/v1/events?token=private-value");
    await expect(decryptWebhookValue({
      ciphertext: stored!.secret_ciphertext, nonce: stored!.secret_nonce
    }, encryptionKey, secretContext)).resolves.toBe(payload.secret);

    const listed = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner);
    expect(listed.status).toBe(200);
    const listPayload = await listed.json() as { endpoints: Array<Record<string, unknown>>; deliveryEnabled: boolean };
    expect(listPayload.deliveryEnabled).toBe(false);
    expect(listPayload.endpoints).toEqual([
      expect.objectContaining({ id: payload.endpoint.id, destinationHost: "hooks.example.com" })
    ]);
    const serialized = JSON.stringify(listPayload);
    expect(serialized).not.toContain(payload.secret);
    expect(serialized).not.toContain("private-value");
    expect(serialized).not.toContain("ciphertext");
  });

  it("requires owner/admin authorization and enforces tenant isolation", async () => {
    const member = await createIdentity("member");
    const viewer = await createIdentity("viewer");
    const memberDenied = await api(`/v1/organizations/${member.organizationId}/webhooks`, member, {
      method: "POST", body: { name: "Member", url: "https://hooks.example.com/member" }
    });
    const viewerDenied = await api(`/v1/organizations/${viewer.organizationId}/webhooks`, viewer, {
      method: "POST", body: { name: "Viewer", url: "https://hooks.example.com/viewer" }
    });
    expect(memberDenied.status).toBe(403);
    expect(viewerDenied.status).toBe(403);

    const admin = await createIdentity("admin");
    const adminCreated = await api(`/v1/organizations/${admin.organizationId}/webhooks`, admin, {
      method: "POST", body: { name: "Admin endpoint", url: "https://hooks.example.com/admin" }
    });
    expect(adminCreated.status).toBe(201);
    expect(await adminCreated.json()).toMatchObject({ deliveryEnabled: false });

    const owner = await createIdentity("owner");
    const foreignRead = await api(`/v1/organizations/${owner.organizationId}/webhooks`, member);
    expect(foreignRead.status).toBe(403);

    const key = "zw_live_" + crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
    await env.DB.prepare("INSERT INTO api_keys (id, organization_id, created_by, name, key_prefix, key_hash) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), owner.organizationId, owner.userId, "Read key", key.slice(0, 16), await sha256(key)).run();
    const apiKeyDenied = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner, { apiKey: key });
    expect(apiKeyDenied.status).toBe(403);
  });

  it("rejects non-HTTPS, credentialed, literal-IP, local and non-default-port destinations", async () => {
    const owner = await createIdentity("owner");
    const invalidUrls = [
      "http://hooks.example.com/events",
      "https://user:pass@hooks.example.com/events",
      "https://hooks.example.com:8443/events",
      "https://127.0.0.1/events",
      "https://2130706433/events",
      "https://[::1]/events",
      "https://service.internal/events",
      "https://service.example.test/events",
      "https://hooks.example.com/events#fragment"
    ];
    for (const url of invalidUrls) {
      const response = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner, {
        method: "POST", body: { name: "Invalid destination", url }
      });
      expect(response.status).toBe(400);
    }
    const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM webhook_endpoints WHERE organization_id = ?")
      .bind(owner.organizationId).first<{ total: number }>();
    expect(count?.total).toBe(0);
  });

  it("rotates secrets, renames endpoints and scrubs ciphertext on removal", async () => {
    const owner = await createIdentity("owner");
    const endpoint = await createEndpoint(owner);
    const rotated = await api(`/v1/organizations/${owner.organizationId}/webhooks/${endpoint.id}/rotate`, owner, {
      method: "POST"
    });
    expect(rotated.status).toBe(200);
    const rotatedPayload = await rotated.json() as { secret: string; deliveryEnabled: boolean };
    expect(rotatedPayload.secret).toMatch(/^whsec_[A-Za-z0-9_-]{43}$/);
    expect(rotatedPayload.secret).not.toBe(endpoint.secret);
    expect(rotatedPayload.deliveryEnabled).toBe(false);

    const row = await env.DB.prepare("SELECT secret_ciphertext, secret_nonce, secret_last4 FROM webhook_endpoints WHERE id = ?")
      .bind(endpoint.id).first<{ secret_ciphertext: string; secret_nonce: string; secret_last4: string }>();
    expect(row?.secret_last4).toBe(rotatedPayload.secret.slice(-4));
    await expect(decryptWebhookValue({
      ciphertext: row!.secret_ciphertext, nonce: row!.secret_nonce
    }, encryptionKey, `zetuwatch:webhook:v1:${owner.organizationId}:${endpoint.id}:secret`))
      .resolves.toBe(rotatedPayload.secret);

    const renamed = await api(`/v1/organizations/${owner.organizationId}/webhooks/${endpoint.id}`, owner, {
      method: "PATCH", body: { name: "Production incident receiver" }
    });
    expect(renamed.status).toBe(200);

    const removed = await api(`/v1/organizations/${owner.organizationId}/webhooks/${endpoint.id}`, owner, {
      method: "DELETE"
    });
    expect(removed.status).toBe(200);
    const scrubbed = await env.DB.prepare("SELECT deleted_at, destination_ciphertext, secret_ciphertext, secret_last4, is_enabled FROM webhook_endpoints WHERE id = ?")
      .bind(endpoint.id).first<{ deleted_at: string; destination_ciphertext: string; secret_ciphertext: string; secret_last4: string; is_enabled: number }>();
    expect(scrubbed).toMatchObject({
      destination_ciphertext: "", secret_ciphertext: "", secret_last4: "----", is_enabled: 0
    });
    expect(scrubbed?.deleted_at).toBeTruthy();
    const listed = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner);
    expect(await listed.json()).toMatchObject({ endpoints: [] });
    const audit = await env.DB.prepare("SELECT COUNT(*) AS total FROM audit_logs WHERE organization_id = ? AND resource_id = ?")
      .bind(owner.organizationId, endpoint.id).first<{ total: number }>();
    expect(audit?.total).toBe(4);
  });

  it("rejects oversized JSON before parsing endpoint configuration", async () => {
    const owner = await createIdentity("owner");
    const response = await exports.default.fetch(new Request(
      `https://api.zetuwatch.test/v1/organizations/${owner.organizationId}/webhooks`,
      {
        method: "POST",
        headers: { cookie: `zw_session=${owner.sessionToken}`, "cf-connecting-ip": crypto.randomUUID(), "content-type": "application/json" },
        body: JSON.stringify({ name: "Receiver", url: "https://hooks.example.com/events", padding: "x".repeat(9_000) })
      }
    ));
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ error: "REQUEST_TOO_LARGE" });
    const count = await env.DB.prepare("SELECT COUNT(*) AS total FROM webhook_endpoints WHERE organization_id = ?")
      .bind(owner.organizationId).first<{ total: number }>();
    expect(count?.total).toBe(0);
  });

  it("enforces the ten-active-endpoint workspace limit and rejects duplicates", async () => {
    const owner = await createIdentity("owner");
    const first = await createEndpoint(owner, "same");
    const duplicate = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner, {
      method: "POST", body: { name: "Duplicate", url: "https://hooks.example.com/same" }
    });
    expect(duplicate.status).toBe(409);

    for (let index = 0; index < 9; index += 1) await createEndpoint(owner, `endpoint-${index}`);
    const overLimit = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner, {
      method: "POST", body: { name: "Eleventh", url: "https://hooks.example.com/eleventh" }
    });
    expect(overLimit.status).toBe(409);
    const list = await api(`/v1/organizations/${owner.organizationId}/webhooks`, owner);
    expect((await list.json() as { endpoints: unknown[] }).endpoints).toHaveLength(10);
    expect(first.id).toBeTruthy();
  });
});
