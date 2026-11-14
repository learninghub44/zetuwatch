import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

type Role = "owner" | "admin" | "member" | "viewer";

interface Identity {
  userId: string;
  organizationId: string;
  sessionToken: string;
  email: string;
}

interface MonitorResponse {
  monitor: { id: string; organization_id?: string; name?: string };
  executionEnabled: boolean;
}

const sha256 = async (value: string): Promise<string> => {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
};

async function createIdentity(role: Role = "owner"): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const sessionToken = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
  const email = `${userId}@example.test`;

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(userId, email, "Integration test user"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Integration workspace", `workspace-${organizationId}`),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)")
      .bind(organizationId, userId, role),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, await sha256(sessionToken), new Date(Date.now() + 60 * 60 * 1000).toISOString())
  ]);

  return { userId, organizationId, sessionToken, email };
}

async function addOwnerToOrganization(identity: Identity): Promise<Identity> {
  const userId = crypto.randomUUID();
  const email = `${userId}@example.test`;
  const sessionToken = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(userId, email, "Second owner"),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'owner')")
      .bind(identity.organizationId, userId),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, await sha256(sessionToken), new Date(Date.now() + 60 * 60 * 1000).toISOString())
  ]);

  return { userId, organizationId: identity.organizationId, sessionToken, email };
}

async function createInvitation(organizationId: string, invitedBy: string, email: string): Promise<string> {
  const token = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");

  await env.DB.prepare(
    "INSERT INTO organization_invitations (id, organization_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, 'member', ?, ?, ?)"
  ).bind(
    crypto.randomUUID(),
    organizationId,
    email,
    await sha256(token),
    invitedBy,
    new Date(Date.now() + 60 * 60 * 1000).toISOString()
  ).run();

  return token;
}

async function createForeignOrganization(): Promise<string> {
  const organizationId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
    .bind(organizationId, "Another tenant", `foreign-${organizationId}`)
    .run();
  return organizationId;
}

async function createMonitor(organizationId: string): Promise<string> {
  const monitorId = crypto.randomUUID();
  await env.DB.prepare(
    "INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)"
  ).bind(monitorId, organizationId, "Private fixture", "https://status.example.com/health").run();
  return monitorId;
}

async function createIncident(monitorId: string): Promise<string> {
  const incidentId = crypto.randomUUID();
  const eventId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, 'investigating', ?)"
    ).bind(incidentId, monitorId, "2026-11-10 09:00:00", "Test incident"),
    env.DB.prepare(
      "INSERT INTO incident_events (id, incident_id, event_type, message, created_at) VALUES (?, ?, 'incident.opened', ?, ?)"
    ).bind(eventId, incidentId, "Incident opened for API integration coverage.", "2026-11-10 09:00:00")
  ]);
  return incidentId;
}

async function createApiKeyFixture(
  identity: Identity,
  options: { expiresAt?: string; revokedAt?: string } = {}
): Promise<{ id: string; secret: string }> {
  const secret = "zw_live_" + Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
  const keyId = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO api_keys (id, organization_id, created_by, name, key_prefix, key_hash, expires_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(
      keyId, identity.organizationId, identity.userId, "Integration read key",
      secret.slice(0, 16), await sha256(secret), options.expiresAt ?? null, options.revokedAt ?? null
    ).run();
  return { id: keyId, secret };
}

function api(
  path: string,
  options: { token?: string; apiKey?: string; method?: string; body?: Record<string, unknown> } = {}
): Promise<Response> {
  const headers = new Headers({ "cf-connecting-ip": crypto.randomUUID() });
  if (options.token) headers.set("cookie", `zw_session=${options.token}`);
  if (options.apiKey) headers.set("authorization", `Bearer ${options.apiKey}`);
  if (options.body) headers.set("content-type", "application/json");

  return exports.default.fetch(new Request(`https://api.zetuwatch.test${path}`, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  }));
}

describe("Worker API tenant isolation", () => {
  it("rejects requests without a verified session", async () => {
    const response = await api(`/v1/monitors?organizationId=${crypto.randomUUID()}`);
    expect(response.status).toBe(401);
    expect(await response.json()).toMatchObject({ error: "UNAUTHENTICATED" });
  });

  it("does not list monitors from an organization the user does not belong to", async () => {
    const identity = await createIdentity("member");
    const foreignOrganizationId = await createForeignOrganization();
    await createMonitor(foreignOrganizationId);

    const response = await api(
      `/v1/monitors?organizationId=${foreignOrganizationId}`,
      { token: identity.sessionToken }
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "FORBIDDEN" });
  });

  it("does not expose another tenant's monitor or check history by ID", async () => {
    const identity = await createIdentity("member");
    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);

    const monitorResponse = await api(`/v1/monitors/${foreignMonitorId}`, { token: identity.sessionToken });
    const checksResponse = await api(`/v1/monitors/${foreignMonitorId}/checks`, { token: identity.sessionToken });

    expect(monitorResponse.status).toBe(403);
    expect(checksResponse.status).toBe(403);
  });

  it("returns persisted check history to an in-tenant viewer without claiming probes are active", async () => {
    const identity = await createIdentity("viewer");
    const monitorId = await createMonitor(identity.organizationId);
    const olderCheckId = crypto.randomUUID();
    const newerCheckId = crypto.randomUUID();

    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO monitor_checks (id, monitor_id, checked_at, is_up, status_code, response_time_ms, error_code) VALUES (?, ?, ?, 1, 200, 34, NULL)"
      ).bind(olderCheckId, monitorId, "2026-11-11 09:00:00"),
      env.DB.prepare(
        "INSERT INTO monitor_checks (id, monitor_id, checked_at, is_up, status_code, response_time_ms, error_code) VALUES (?, ?, ?, 0, 503, 87, 'HTTP_STATUS_MISMATCH')"
      ).bind(newerCheckId, monitorId, "2026-11-11 09:05:00")
    ]);

    const response = await api("/v1/monitors/" + monitorId + "/checks", {
      token: identity.sessionToken
    });

    expect(response.status).toBe(200);
    const payload = await response.json() as {
      executionEnabled: boolean;
      checks: Array<{
        id: string;
        is_up: number;
        status_code: number;
        response_time_ms: number;
        error_code: string | null;
      }>;
    };
    expect(payload.executionEnabled).toBe(false);
    expect(payload.checks.map(check => check.id)).toEqual([newerCheckId, olderCheckId]);
    expect(payload.checks[0]).toMatchObject({
      is_up: 0,
      status_code: 503,
      response_time_ms: 87,
      error_code: "HTTP_STATUS_MISMATCH"
    });
  });

  it("does not allow a tenant member to create a monitor in another organization", async () => {
    const identity = await createIdentity("member");
    const foreignOrganizationId = await createForeignOrganization();

    const response = await api("/v1/monitors", {
      token: identity.sessionToken,
      method: "POST",
      body: {
        organizationId: foreignOrganizationId,
        name: "Cross-tenant attempt",
        targetUrl: "https://status.example.com/health",
        monitorType: "http",
        method: "GET",
        expectedStatus: 200,
        intervalSeconds: 300,
        timeoutMs: 5000
      }
    });

    expect(response.status).toBe(403);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM monitors WHERE organization_id = ?")
      .bind(foreignOrganizationId).first<{ count: number }>();
    expect(count?.count).toBe(0);
  });

  it("allows a member to create and read an in-tenant monitor but not delete it", async () => {
    const identity = await createIdentity("member");
    const createResponse = await api("/v1/monitors", {
      token: identity.sessionToken,
      method: "POST",
      body: {
        organizationId: identity.organizationId,
        name: "Public status endpoint",
        targetUrl: "https://status.example.com/health",
        monitorType: "http",
        method: "GET",
        expectedStatus: 200,
        intervalSeconds: 300,
        timeoutMs: 5000
      }
    });

    expect(createResponse.status).toBe(201);
    const created = await createResponse.json() as MonitorResponse;
    expect(created.executionEnabled).toBe(false);
    expect(created.monitor.id).toBeTruthy();

    const readResponse = await api(`/v1/monitors/${created.monitor.id}`, { token: identity.sessionToken });
    expect(readResponse.status).toBe(200);

    const deleteResponse = await api(`/v1/monitors/${created.monitor.id}`, {
      token: identity.sessionToken,
      method: "DELETE"
    });
    expect(deleteResponse.status).toBe(403);
  });

  it("keeps viewers read-only for monitor creation and updates", async () => {
    const identity = await createIdentity("viewer");
    const monitorId = await createMonitor(identity.organizationId);

    const readResponse = await api(`/v1/monitors/${monitorId}`, { token: identity.sessionToken });
    const createResponse = await api("/v1/monitors", {
      token: identity.sessionToken,
      method: "POST",
      body: {
        organizationId: identity.organizationId,
        name: "Viewer write attempt",
        targetUrl: "https://status.example.com/health",
        monitorType: "http",
        method: "GET",
        expectedStatus: 200,
        intervalSeconds: 300,
        timeoutMs: 5000
      }
    });
    const updateResponse = await api(`/v1/monitors/${monitorId}`, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { name: "Viewer update attempt" }
    });

    expect(readResponse.status).toBe(200);
    expect(createResponse.status).toBe(403);
    expect(updateResponse.status).toBe(403);
  });

  it("does not expose team membership for another tenant", async () => {
    const identity = await createIdentity("member");
    const foreignOrganizationId = await createForeignOrganization();

    const response = await api(
      `/v1/organizations/${foreignOrganizationId}/members`,
      { token: identity.sessionToken }
    );

    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: "FORBIDDEN" });
  });
  it("consumes a team invitation only once under concurrent acceptance", async () => {
    const invitee = await createIdentity("member");
    const inviter = await createIdentity("owner");
    const invitationToken = await createInvitation(inviter.organizationId, inviter.userId, invitee.email);

    const responses = await Promise.all([
      api("/v1/invitations/accept", {
        token: invitee.sessionToken,
        method: "POST",
        body: { token: invitationToken }
      }),
      api("/v1/invitations/accept", {
        token: invitee.sessionToken,
        method: "POST",
        body: { token: invitationToken }
      })
    ]);

    const statuses = responses.map(response => response.status);
    expect(statuses.filter(status => status === 200)).toHaveLength(1);
    expect(statuses.filter(status => status !== 200).every(status => status === 400 || status === 409)).toBe(true);

    const membership = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = ? AND user_id = ?"
    ).bind(inviter.organizationId, invitee.userId).first<{ count: number }>();
    const acceptedEvents = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM audit_logs WHERE organization_id = ? AND action = 'team.invitation_accepted'"
    ).bind(inviter.organizationId).first<{ count: number }>();

    expect(membership?.count).toBe(1);
    expect(acceptedEvents?.count).toBe(1);
  });

  it("serializes concurrent owner demotions and preserves one workspace owner", async () => {
    const firstOwner = await createIdentity("owner");
    const secondOwner = await addOwnerToOrganization(firstOwner);

    const responses = await Promise.all([
      api(`/v1/organizations/${firstOwner.organizationId}/members/${secondOwner.userId}`, {
        token: firstOwner.sessionToken,
        method: "PATCH",
        body: { role: "admin" }
      }),
      api(`/v1/organizations/${firstOwner.organizationId}/members/${firstOwner.userId}`, {
        token: secondOwner.sessionToken,
        method: "PATCH",
        body: { role: "admin" }
      })
    ]);

    expect(responses.filter(response => response.status === 200)).toHaveLength(1);

    const ownerCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM organization_members WHERE organization_id = ? AND role = 'owner'"
    ).bind(firstOwner.organizationId).first<{ count: number }>();
    const roles = await env.DB.prepare(
      "SELECT role FROM organization_members WHERE organization_id = ? ORDER BY role"
    ).bind(firstOwner.organizationId).all<{ role: string }>();

    expect(ownerCount?.count).toBe(1);
    expect(roles.results.map(row => row.role).sort()).toEqual(["admin", "owner"]);
  });


  it("soft-deletes monitors while retaining check and incident history", async () => {
    const identity = await createIdentity("owner");
    const monitorId = await createMonitor(identity.organizationId);
    const incidentId = await createIncident(monitorId);
    await env.DB.prepare(
      "INSERT INTO monitor_checks (id, monitor_id, checked_at, is_up, status_code, response_time_ms) VALUES (?, ?, ?, 1, 200, 24)"
    ).bind(crypto.randomUUID(), monitorId, "2026-11-11 09:00:00").run();

    const deleted = await api("/v1/monitors/" + monitorId, {
      token: identity.sessionToken,
      method: "DELETE"
    });
    expect(deleted.status).toBe(200);
    expect(await deleted.json()).toMatchObject({ message: "Monitor deleted. Check history and incident timelines are retained." });

    const list = await api("/v1/monitors?organizationId=" + identity.organizationId, {
      token: identity.sessionToken
    });
    const monitorList = await list.json() as { monitors: Array<{ id: string }> };
    expect(monitorList.monitors.some(monitor => monitor.id === monitorId)).toBe(false);

    const detail = await api("/v1/monitors/" + monitorId, { token: identity.sessionToken });
    const checks = await api("/v1/monitors/" + monitorId + "/checks", { token: identity.sessionToken });
    expect(detail.status).toBe(404);
    expect(checks.status).toBe(404);

    const incidentDetail = await api("/v1/incidents/" + incidentId, { token: identity.sessionToken });
    expect(incidentDetail.status).toBe(200);
    const timeline = await incidentDetail.json() as { incident: { monitorId: string }; events: Array<{ eventType: string }> };
    expect(timeline.incident.monitorId).toBe(monitorId);
    expect(timeline.events.map(event => event.eventType)).toEqual(["incident.opened"]);

    const retained = await env.DB.prepare(
      "SELECT deleted_at, deleted_by, is_enabled FROM monitors WHERE id = ?"
    ).bind(monitorId).first<{ deleted_at: string | null; deleted_by: string | null; is_enabled: number }>();
    const checkCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM monitor_checks WHERE monitor_id = ?"
    ).bind(monitorId).first<{ count: number }>();
    const incidentCount = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM incidents WHERE id = ?"
    ).bind(incidentId).first<{ count: number }>();

    expect(retained?.deleted_at).toBeTruthy();
    expect(retained?.deleted_by).toBe(identity.userId);
    expect(retained?.is_enabled).toBe(0);
    expect(checkCount?.count).toBe(1);
    expect(incidentCount?.count).toBe(1);
  });

  it("lists incidents only inside the selected organization", async () => {
    const identity = await createIdentity("member");
    const ownMonitorId = await createMonitor(identity.organizationId);
    const ownIncidentId = await createIncident(ownMonitorId);
    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);
    await createIncident(foreignMonitorId);

    const response = await api(
      `/v1/incidents?organizationId=${identity.organizationId}`,
      { token: identity.sessionToken }
    );
    expect(response.status).toBe(200);
    const payload = await response.json() as { incidents: Array<{ id: string; monitorId: string }> };
    expect(payload.incidents.map((incident) => incident.id)).toEqual([ownIncidentId]);
    expect(payload.incidents[0].monitorId).toBe(ownMonitorId);

    const foreignList = await api(
      `/v1/incidents?organizationId=${foreignOrganizationId}`,
      { token: identity.sessionToken }
    );
    expect(foreignList.status).toBe(403);
  });

  it("returns incident timelines only to members of the owning organization", async () => {
    const identity = await createIdentity("viewer");
    const ownMonitorId = await createMonitor(identity.organizationId);
    const ownIncidentId = await createIncident(ownMonitorId);

    const ownResponse = await api(`/v1/incidents/${ownIncidentId}`, {
      token: identity.sessionToken
    });
    expect(ownResponse.status).toBe(200);
    const ownPayload = await ownResponse.json() as {
      incident: { id: string; organizationId: string };
      events: Array<{ eventType: string }>;
    };
    expect(ownPayload.incident.id).toBe(ownIncidentId);
    expect(ownPayload.incident.organizationId).toBe(identity.organizationId);
    expect(ownPayload.events.map((event) => event.eventType)).toEqual(["incident.opened"]);

    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);
    const foreignIncidentId = await createIncident(foreignMonitorId);
    const foreignResponse = await api(`/v1/incidents/${foreignIncidentId}`, {
      token: identity.sessionToken
    });
    expect(foreignResponse.status).toBe(403);
  });

  it("allows owners to pause monitors, clears leases and audits only the first state change", async () => {
    const identity = await createIdentity("owner");
    const monitorId = await createMonitor(identity.organizationId);
    await env.DB.prepare(
      "UPDATE monitors SET check_lease_token = ?, check_lease_until = ? WHERE id = ?"
    ).bind("lease-token-for-pause-12345", new Date(Date.now() + 60_000).toISOString(), monitorId).run();

    const first = await api(`/v1/monitors/${monitorId}/pause`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(first.status).toBe(200);
    expect(await first.json()).toMatchObject({
      changed: true,
      monitor: { id: monitorId, isEnabled: false },
      executionEnabled: false
    });

    const second = await api(`/v1/monitors/${monitorId}/pause`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(second.status).toBe(200);
    expect(await second.json()).toMatchObject({ changed: false, monitor: { isEnabled: false } });

    const stored = await env.DB.prepare(
      "SELECT is_enabled, check_lease_token, check_lease_until FROM monitors WHERE id = ?"
    ).bind(monitorId).first<{ is_enabled: number; check_lease_token: string | null; check_lease_until: string | null }>();
    const audit = await env.DB.prepare(
      "SELECT COUNT(*) AS count FROM audit_logs WHERE organization_id = ? AND action = 'monitor.paused' AND resource_id = ?"
    ).bind(identity.organizationId, monitorId).first<{ count: number }>();
    expect(stored).toMatchObject({ is_enabled: 0, check_lease_token: null, check_lease_until: null });
    expect(audit?.count).toBe(1);
  });

  it("allows members to resume monitors and makes them due without running a probe", async () => {
    const identity = await createIdentity("member");
    const monitorId = await createMonitor(identity.organizationId);
    await env.DB.prepare(
      "UPDATE monitors SET is_enabled = 0, check_lease_token = ?, check_lease_until = ? WHERE id = ?"
    ).bind("expired-paused-lease-12345", new Date(Date.now() + 60_000).toISOString(), monitorId).run();

    const response = await api(`/v1/monitors/${monitorId}/resume`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      changed: true,
      monitor: { id: monitorId, isEnabled: true },
      executionEnabled: false
    });

    const stored = await env.DB.prepare(
      "SELECT is_enabled, check_lease_token, check_lease_until, CASE WHEN next_check_at <= CURRENT_TIMESTAMP THEN 1 ELSE 0 END AS is_due FROM monitors WHERE id = ?"
    ).bind(monitorId).first<{ is_enabled: number; check_lease_token: string | null; check_lease_until: string | null; is_due: number }>();
    expect(stored).toMatchObject({
      is_enabled: 1,
      check_lease_token: null,
      check_lease_until: null,
      is_due: 1
    });
  });

  it("keeps monitor pause and resume unavailable to viewers", async () => {
    const identity = await createIdentity("viewer");
    const monitorId = await createMonitor(identity.organizationId);
    const response = await api(`/v1/monitors/${monitorId}/pause`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(response.status).toBe(403);
    const stored = await env.DB.prepare("SELECT is_enabled FROM monitors WHERE id = ?")
      .bind(monitorId).first<{ is_enabled: number }>();
    expect(stored?.is_enabled).toBe(1);
  });

  it("does not allow a workspace member to pause another tenant's monitor", async () => {
    const identity = await createIdentity("member");
    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);
    const response = await api(`/v1/monitors/${foreignMonitorId}/pause`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(response.status).toBe(403);
    const stored = await env.DB.prepare("SELECT is_enabled FROM monitors WHERE id = ?")
      .bind(foreignMonitorId).first<{ is_enabled: number }>();
    expect(stored?.is_enabled).toBe(1);
  });

  it("does not expose archived monitors through pause or resume actions", async () => {
    const identity = await createIdentity("owner");
    const monitorId = await createMonitor(identity.organizationId);
    await env.DB.prepare("UPDATE monitors SET deleted_at = CURRENT_TIMESTAMP, is_enabled = 0 WHERE id = ?")
      .bind(monitorId).run();
    const response = await api(`/v1/monitors/${monitorId}/resume`, {
      token: identity.sessionToken,
      method: "POST"
    });
    expect(response.status).toBe(404);
  });



  it("creates a read-only API key once, lists metadata without secrets, records use and revokes it", async () => {
    const identity = await createIdentity("owner");
    const monitorId = await createMonitor(identity.organizationId);
    const createResponse = await api("/v1/organizations/" + identity.organizationId + "/api-keys", {
      token: identity.sessionToken,
      method: "POST",
      body: { name: "CI read integration", expiresInDays: 30 }
    });
    expect(createResponse.status).toBe(201);
    const created = await createResponse.json() as {
      apiKey: { id: string; name: string; keyPrefix: string; expiresAt: string };
      secret: string;
    };
    expect(created.secret).toMatch(/^zw_live_[A-Za-z0-9_-]{40,64}$/);
    expect(created.apiKey).toMatchObject({ name: "CI read integration" });
    expect(created.apiKey.keyPrefix).toBe(created.secret.slice(0, 16));

    const stored = await env.DB.prepare("SELECT key_hash, last_used_at FROM api_keys WHERE id = ?")
      .bind(created.apiKey.id).first<{ key_hash: string; last_used_at: string | null }>();
    expect(stored?.key_hash).toBe(await sha256(created.secret));
    expect(stored?.key_hash).not.toContain(created.secret);

    const listed = await api("/v1/organizations/" + identity.organizationId + "/api-keys", {
      token: identity.sessionToken
    });
    expect(listed.status).toBe(200);
    const listPayload = await listed.json() as { apiKeys: Array<Record<string, unknown>> };
    expect(listPayload.apiKeys).toHaveLength(1);
    expect(listPayload.apiKeys[0]).toMatchObject({ id: created.apiKey.id, key_prefix: created.apiKey.keyPrefix });
    expect(JSON.stringify(listPayload)).not.toContain(created.secret);
    expect(listPayload.apiKeys[0]).not.toHaveProperty("key_hash");

    const read = await api("/v1/monitors?organizationId=" + identity.organizationId, {
      apiKey: created.secret
    });
    expect(read.status).toBe(200);
    expect((await read.json() as { monitors: Array<{ id: string }> }).monitors[0]?.id).toBe(monitorId);
    const used = await env.DB.prepare("SELECT last_used_at FROM api_keys WHERE id = ?")
      .bind(created.apiKey.id).first<{ last_used_at: string | null }>();
    expect(used?.last_used_at).toBeTruthy();

    const revoked = await api("/v1/organizations/" + identity.organizationId + "/api-keys/" + created.apiKey.id, {
      token: identity.sessionToken,
      method: "DELETE"
    });
    expect(revoked.status).toBe(200);
    expect(await revoked.json()).toMatchObject({ changed: true });

    const rejected = await api("/v1/monitors?organizationId=" + identity.organizationId, {
      apiKey: created.secret
    });
    expect(rejected.status).toBe(401);
    const audit = await env.DB.prepare("SELECT action FROM audit_logs WHERE organization_id = ? AND resource_id = ? ORDER BY action")
      .bind(identity.organizationId, created.apiKey.id).all<{ action: string }>();
    expect(audit.results.map(row => row.action)).toEqual(["api_key.created", "api_key.revoked"]);
  });

  it("restricts read-only API keys to their workspace and rejects every monitor mutation", async () => {
    const identity = await createIdentity("owner");
    const ownMonitorId = await createMonitor(identity.organizationId);
    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);
    const key = await createApiKeyFixture(identity);

    expect((await api("/v1/monitors?organizationId=" + identity.organizationId, { apiKey: key.secret })).status).toBe(200);
    expect((await api("/v1/monitors?organizationId=" + foreignOrganizationId, { apiKey: key.secret })).status).toBe(403);
    expect((await api("/v1/monitors/" + ownMonitorId, { apiKey: key.secret })).status).toBe(200);
    expect((await api("/v1/monitors/" + ownMonitorId + "/checks", { apiKey: key.secret })).status).toBe(200);
    expect((await api("/v1/monitors/" + foreignMonitorId, { apiKey: key.secret })).status).toBe(403);

    const create = await api("/v1/monitors", {
      apiKey: key.secret,
      method: "POST",
      body: {
        organizationId: identity.organizationId,
        name: "Should be rejected",
        targetUrl: "https://status.example.com/health"
      }
    });
    const pause = await api("/v1/monitors/" + ownMonitorId + "/pause", {
      apiKey: key.secret,
      method: "POST"
    });
    const update = await api("/v1/monitors/" + ownMonitorId, {
      apiKey: key.secret,
      method: "PATCH",
      body: { name: "Changed by API key" }
    });
    const remove = await api("/v1/monitors/" + ownMonitorId, {
      apiKey: key.secret,
      method: "DELETE"
    });
    expect([create.status, pause.status, update.status, remove.status]).toEqual([403, 403, 403, 403]);
    const stored = await env.DB.prepare("SELECT is_enabled, name FROM monitors WHERE id = ?")
      .bind(ownMonitorId).first<{ is_enabled: number; name: string }>();
    expect(stored).toMatchObject({ is_enabled: 1, name: "Private fixture" });
  });

  it("keeps API keys out of authentication and team-management endpoints", async () => {
    const identity = await createIdentity("owner");
    const key = await createApiKeyFixture(identity);
    const me = await api("/auth/me", { apiKey: key.secret });
    const members = await api("/v1/organizations/" + identity.organizationId + "/members", {
      apiKey: key.secret
    });
    const keyManagement = await api("/v1/organizations/" + identity.organizationId + "/api-keys", {
      apiKey: key.secret
    });
    expect([me.status, members.status, keyManagement.status]).toEqual([403, 403, 403]);
  });

  it("exposes only public incident timeline events to read-only API keys", async () => {
    const identity = await createIdentity("owner");
    const monitorId = await createMonitor(identity.organizationId);
    const incidentId = await createIncident(monitorId);
    await env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, visibility, actor_user_id) VALUES (?, ?, 'incident.update', ?, 'public', ?)")
      .bind(crypto.randomUUID(), incidentId, "Public customer update", identity.userId).run();
    const key = await createApiKeyFixture(identity);

    const response = await api("/v1/incidents/" + incidentId, { apiKey: key.secret });
    expect(response.status).toBe(200);
    const payload = await response.json() as { events: Array<{ message: string; visibility: string }> };
    expect(payload.events).toEqual([
      expect.objectContaining({ message: "Public customer update", visibility: "public" })
    ]);
  });

  it("rejects expired and revoked API keys and prevents members/viewers from creating keys", async () => {
    const owner = await createIdentity("owner");
    const expired = await createApiKeyFixture(owner, { expiresAt: "2020-01-01T00:00:00.000Z" });
    const revoked = await createApiKeyFixture(owner, { revokedAt: "2026-11-13T09:00:00.000Z" });
    expect((await api("/v1/monitors?organizationId=" + owner.organizationId, { apiKey: expired.secret })).status).toBe(401);
    expect((await api("/v1/monitors?organizationId=" + owner.organizationId, { apiKey: revoked.secret })).status).toBe(401);

    for (const role of ["member", "viewer"] as const) {
      const identity = await createIdentity(role);
      const response = await api("/v1/organizations/" + identity.organizationId + "/api-keys", {
        token: identity.sessionToken,
        method: "POST",
        body: { name: "Not permitted", expiresInDays: 90 }
      });
      expect(response.status).toBe(403);
    }
  });


  it("prefers a supplied read-only bearer key over an ambient session cookie", async () => {
    const identity = await createIdentity("owner");
    const key = await createApiKeyFixture(identity);
    const body = {
      organizationId: identity.organizationId,
      name: "Must remain read-only",
      targetUrl: "https://status.example.com/health"
    };
    const writeWithBothCredentials = await api("/v1/monitors", {
      token: identity.sessionToken,
      apiKey: key.secret,
      method: "POST",
      body
    });
    expect(writeWithBothCredentials.status).toBe(403);

    const invalidBearerWithValidCookie = await api("/v1/monitors?organizationId=" + identity.organizationId, {
      token: identity.sessionToken,
      apiKey: "zw_live_" + "x".repeat(43)
    });
    expect(invalidBearerWithValidCookie.status).toBe(401);

    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM monitors WHERE organization_id = ?")
      .bind(identity.organizationId).first<{ count: number }>();
    expect(count?.count).toBe(0);
  });

});


describe("Status pages", () => {
  it("creates a tenant-scoped draft with selected components and an audit event", async () => {
    const owner = await createIdentity("owner");
    const monitorId = await createMonitor(owner.organizationId);
    const response = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Customer status", slug: "customer-status", description: "Public service updates", monitorIds: [monitorId] }
    });

    expect(response.status).toBe(201);
    const payload = await response.json() as { statusPage: { id: string; slug: string; isPublished: boolean; componentCount: number }; publicPath: string };
    expect(payload.statusPage).toMatchObject({ slug: "customer-status", isPublished: false, componentCount: 1 });
    expect(payload.publicPath).toBe("/status.html?slug=customer-status");

    const stored = await env.DB.prepare("SELECT organization_id, is_published, archived_at FROM status_pages WHERE id = ?")
      .bind(payload.statusPage.id).first<{ organization_id: string; is_published: number; archived_at: string | null }>();
    expect(stored).toMatchObject({ organization_id: owner.organizationId, is_published: 0, archived_at: null });

    const components = await env.DB.prepare("SELECT monitor_id, position FROM status_page_monitors WHERE page_id = ?")
      .bind(payload.statusPage.id).all<{ monitor_id: string; position: number }>();
    expect(components.results).toEqual([{ monitor_id: monitorId, position: 0 }]);

    const audit = await env.DB.prepare("SELECT action FROM audit_logs WHERE organization_id = ? AND resource_id = ?")
      .bind(owner.organizationId, payload.statusPage.id).first<{ action: string }>();
    expect(audit?.action).toBe("status_page.created");
    expect((await api("/public/status-pages/customer-status")).status).toBe(404);
  });

  it("publishes a public view with unknown health and only customer-visible incident updates", async () => {
    const owner = await createIdentity("owner");
    const monitorId = await createMonitor(owner.organizationId);
    const created = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Public status", slug: "public-status", monitorIds: [monitorId] }
    });
    expect(created.status).toBe(201);
    const page = (await created.json() as { statusPage: { id: string } }).statusPage;

    const incidentId = await createIncident(monitorId);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, visibility) VALUES (?, ?, 'incident.update', ?, 'internal')")
        .bind(crypto.randomUUID(), incidentId, "Private investigation detail"),
      env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, visibility) VALUES (?, ?, 'incident.update', ?, 'public')")
        .bind(crypto.randomUUID(), incidentId, "We are investigating an issue affecting this service.")
    ]);

    const publish = await api("/v1/status-pages/" + page.id + "/publish", {
      token: owner.sessionToken,
      method: "POST",
      body: { published: true }
    });
    expect(publish.status).toBe(200);
    expect(await publish.json()).toMatchObject({ changed: true });

    const response = await api("/public/status-pages/public-status");
    expect(response.status).toBe(200);
    const payload = await response.json() as {
      overallStatus: string;
      monitoringEnabled: boolean;
      page: { name: string; slug: string };
      components: Array<{ name: string; status: string; state: string }>;
      updates: Array<{ message: string }>;
    };
    expect(payload).toMatchObject({
      overallStatus: "unknown",
      monitoringEnabled: false,
      page: { name: "Public status", slug: "public-status" },
      components: [{ name: "Private fixture", status: "unknown", state: "awaiting_first_check" }]
    });
    expect(payload.updates.map(update => update.message)).toContain("We are investigating an issue affecting this service.");
    expect(payload.updates.map(update => update.message)).not.toContain("Private investigation detail");
    const serialized = JSON.stringify(payload);
    expect(serialized).not.toContain("status.example.com");
    expect(serialized).not.toContain(monitorId);
    expect(serialized).not.toContain("organizationId");
  });

  it("rejects cross-tenant components and invalid slugs without creating a page", async () => {
    const owner = await createIdentity("owner");
    const foreignOrganizationId = await createForeignOrganization();
    const foreignMonitorId = await createMonitor(foreignOrganizationId);

    const crossTenant = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Cross tenant", slug: "cross-tenant", monitorIds: [foreignMonitorId] }
    });
    const invalidSlug = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Invalid slug", slug: "not/a/slug", monitorIds: [] }
    });
    expect([crossTenant.status, invalidSlug.status]).toEqual([400, 400]);

    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM status_pages WHERE organization_id = ?")
      .bind(owner.organizationId).first<{ count: number }>();
    expect(count?.count).toBe(0);

    const pageId = crypto.randomUUID();
    await env.DB.prepare("INSERT INTO status_pages (id, organization_id, name, slug) VALUES (?, ?, ?, ?)")
      .bind(pageId, owner.organizationId, "Direct fixture", "direct-fixture").run();
    await expect(env.DB.prepare("INSERT INTO status_page_monitors (page_id, monitor_id, position) VALUES (?, ?, 0)")
      .bind(pageId, foreignMonitorId).run()).rejects.toThrow(/STATUS_PAGE_MONITOR_TENANT_MISMATCH/);
    await env.DB.prepare("DELETE FROM status_pages WHERE id = ?").bind(pageId).run();
  });

  it("allows workspace members to list pages but reserves mutations for owners and admins", async () => {
    const owner = await createIdentity("owner");
    const monitorId = await createMonitor(owner.organizationId);
    const created = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Team page", slug: "team-page", monitorIds: [monitorId] }
    });
    const pageId = (await created.json() as { statusPage: { id: string } }).statusPage.id;

    const viewer = await createIdentity("viewer");
    await env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, 'viewer')")
      .bind(owner.organizationId, viewer.userId).run();

    const list = await api("/v1/organizations/" + owner.organizationId + "/status-pages", { token: viewer.sessionToken });
    const create = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: viewer.sessionToken,
      method: "POST",
      body: { name: "Viewer page", slug: "viewer-page", monitorIds: [monitorId] }
    });
    const publish = await api("/v1/status-pages/" + pageId + "/publish", {
      token: viewer.sessionToken,
      method: "POST",
      body: { published: true }
    });
    expect(list.status).toBe(200);
    expect((await list.json() as { statusPages: unknown[] }).statusPages).toHaveLength(1);
    expect([create.status, publish.status]).toEqual([403, 403]);
  });

  it("requires at least one configured component to publish and archives pages without exposing them publicly", async () => {
    const owner = await createIdentity("owner");
    const empty = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Empty page", slug: "empty-page", monitorIds: [] }
    });
    expect(empty.status).toBe(201);
    const emptyId = (await empty.json() as { statusPage: { id: string } }).statusPage.id;
    const publishEmpty = await api("/v1/status-pages/" + emptyId + "/publish", {
      token: owner.sessionToken,
      method: "POST",
      body: { published: true }
    });
    expect(publishEmpty.status).toBe(409);

    const monitorId = await createMonitor(owner.organizationId);
    const created = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Archive me", slug: "archive-me", monitorIds: [monitorId] }
    });
    const pageId = (await created.json() as { statusPage: { id: string } }).statusPage.id;
    expect((await api("/v1/status-pages/" + pageId + "/publish", {
      token: owner.sessionToken, method: "POST", body: { published: true }
    })).status).toBe(200);
    const archived = await api("/v1/status-pages/" + pageId, { token: owner.sessionToken, method: "DELETE" });
    expect(archived.status).toBe(200);
    expect((await api("/public/status-pages/archive-me")).status).toBe(404);

    const stored = await env.DB.prepare("SELECT is_published, archived_at FROM status_pages WHERE id = ?")
      .bind(pageId).first<{ is_published: number; archived_at: string | null }>();
    expect(stored?.is_published).toBe(0);
    expect(stored?.archived_at).toBeTruthy();
  });

  it("prevents an already published page from losing its final component through editing", async () => {
    const owner = await createIdentity("owner");
    const monitorId = await createMonitor(owner.organizationId);
    const created = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Keep a component", slug: "keep-a-component", monitorIds: [monitorId] }
    });
    expect(created.status).toBe(201);
    const pageId = (await created.json() as { statusPage: { id: string } }).statusPage.id;
    expect((await api("/v1/status-pages/" + pageId + "/publish", {
      token: owner.sessionToken, method: "POST", body: { published: true }
    })).status).toBe(200);

    const update = await api("/v1/status-pages/" + pageId, {
      token: owner.sessionToken,
      method: "PATCH",
      body: { monitorIds: [] }
    });
    expect(update.status).toBe(409);
    const association = await env.DB.prepare("SELECT monitor_id FROM status_page_monitors WHERE page_id = ?")
      .bind(pageId).first<{ monitor_id: string }>();
    expect(association?.monitor_id).toBe(monitorId);
  });

  it("automatically unpublishes a page when its final monitor is soft-deleted", async () => {
    const owner = await createIdentity("owner");
    const monitorId = await createMonitor(owner.organizationId);
    const created = await api("/v1/organizations/" + owner.organizationId + "/status-pages", {
      token: owner.sessionToken,
      method: "POST",
      body: { name: "Monitor lifecycle", slug: "monitor-lifecycle", monitorIds: [monitorId] }
    });
    expect(created.status).toBe(201);
    const pageId = (await created.json() as { statusPage: { id: string } }).statusPage.id;
    expect((await api("/v1/status-pages/" + pageId + "/publish", {
      token: owner.sessionToken, method: "POST", body: { published: true }
    })).status).toBe(200);

    const deleted = await api("/v1/monitors/" + monitorId, { token: owner.sessionToken, method: "DELETE" });
    expect(deleted.status).toBe(200);
    const page = await env.DB.prepare("SELECT is_published, archived_at FROM status_pages WHERE id = ?")
      .bind(pageId).first<{ is_published: number; archived_at: string | null }>();
    expect(page).toMatchObject({ is_published: 0, archived_at: null });
    expect((await api("/public/status-pages/monitor-lifecycle")).status).toBe(404);
  });

  it("does not allow read-only API keys to access status page administration", async () => {
    const owner = await createIdentity("owner");
    const key = await createApiKeyFixture(owner);
    const response = await api("/v1/organizations/" + owner.organizationId + "/status-pages", { apiKey: key.secret });
    expect(response.status).toBe(403);
  });
});
