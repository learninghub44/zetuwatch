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


});
