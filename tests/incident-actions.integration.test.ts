import { env, exports } from "cloudflare:workers";
import { describe, expect, it } from "vitest";

type Role = "owner" | "admin" | "member" | "viewer";

interface Identity {
  userId: string;
  organizationId: string;
  sessionToken: string;
}

async function createIdentity(role: Role): Promise<Identity> {
  const userId = crypto.randomUUID();
  const organizationId = crypto.randomUUID();
  const sessionToken = Array.from(
    crypto.getRandomValues(new Uint8Array(32)),
    byte => byte.toString(16).padStart(2, "0")
  ).join("");
  const tokenHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(sessionToken));
  const tokenHashHex = Array.from(new Uint8Array(tokenHash), byte => byte.toString(16).padStart(2, "0")).join("");

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (id, email, display_name, email_verified_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
    ).bind(userId, userId + "@example.test", "Incident Operator"),
    env.DB.prepare("INSERT INTO organizations (id, name, slug) VALUES (?, ?, ?)")
      .bind(organizationId, "Incident workspace", "incident-" + organizationId),
    env.DB.prepare("INSERT INTO organization_members (organization_id, user_id, role) VALUES (?, ?, ?)")
      .bind(organizationId, userId, role),
    env.DB.prepare("INSERT INTO auth_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)")
      .bind(crypto.randomUUID(), userId, tokenHashHex, new Date(Date.now() + 60 * 60 * 1000).toISOString())
  ]);

  return { userId, organizationId, sessionToken };
}

async function createIncident(organizationId: string, status = "investigating"): Promise<string> {
  const monitorId = crypto.randomUUID();
  const incidentId = crypto.randomUUID();
  await env.DB.batch([
    env.DB.prepare("INSERT INTO monitors (id, organization_id, name, target_url) VALUES (?, ?, ?, ?)")
      .bind(monitorId, organizationId, "API health", "https://api.example.com/health"),
    env.DB.prepare("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES (?, ?, ?, ?, ?)")
      .bind(incidentId, monitorId, new Date().toISOString(), status, "Monitor failed consecutive checks."),
    env.DB.prepare("INSERT INTO incident_events (id, incident_id, event_type, message, created_at) VALUES (?, ?, 'incident.opened', ?, ?)")
      .bind(crypto.randomUUID(), incidentId, "Incident opened after confirmed failures.", new Date().toISOString())
  ]);
  return incidentId;
}

function api(
  path: string,
  options: { token: string; method?: string; body?: Record<string, unknown> }
): Promise<Response> {
  const headers = new Headers({ cookie: "zw_session=" + options.token, "cf-connecting-ip": crypto.randomUUID() });
  if (options.body) headers.set("content-type", "application/json");
  return exports.default.fetch(new Request("https://api.zetuwatch.test" + path, {
    method: options.method ?? "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  }));
}

describe("incident actions and authored timeline", () => {
  it("records internal and public notes with the authenticated actor", async () => {
    const identity = await createIdentity("member");
    const incidentId = await createIncident(identity.organizationId);

    const internal = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "We are checking the upstream dependency." }
    });
    const publicUpdate = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "We have identified an upstream issue.", visibility: "public" }
    });

    expect(internal.status).toBe(201);
    expect(publicUpdate.status).toBe(201);
    const detail = await api("/v1/incidents/" + incidentId, { token: identity.sessionToken });
    expect(detail.status).toBe(200);
    const payload = await detail.json() as {
      events: Array<{ eventType: string; message: string; visibility: string; actorUserId: string; actorName: string }>;
    };
    expect(payload.events).toHaveLength(3);
    const internalEvent = payload.events.find(event => event.message === "We are checking the upstream dependency.");
    const publicEvent = payload.events.find(event => event.message === "We have identified an upstream issue.");
    expect(internalEvent).toMatchObject({
      eventType: "incident.update",
      visibility: "internal",
      actorUserId: identity.userId,
      actorName: "Incident Operator"
    });
    expect(publicEvent).toMatchObject({
      eventType: "incident.update",
      visibility: "public",
      actorUserId: identity.userId
    });
  });

  it("allows members to advance the incident state and records each transition", async () => {
    const identity = await createIdentity("member");
    const incidentId = await createIncident(identity.organizationId);

    const identified = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "identified", message: "The database provider is degraded.", visibility: "public" }
    });
    expect(identified.status).toBe(200);
    expect(await identified.json()).toMatchObject({ status: "identified" });

    const monitoring = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "monitoring" }
    });
    expect(monitoring.status).toBe(200);

    const resolved = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "resolved", message: "Service has recovered." }
    });
    expect(resolved.status).toBe(200);

    const detail = await api("/v1/incidents/" + incidentId, { token: identity.sessionToken });
    const payload = await detail.json() as {
      incident: { status: string; resolvedAt: string | null };
      events: Array<{ eventType: string; visibility: string; actorUserId: string | null }>;
    };
    expect(payload.incident.status).toBe("resolved");
    expect(payload.incident.resolvedAt).toBeTruthy();
    const statusEvents = payload.events.filter(event => event.eventType === "incident.status_changed");
    expect(statusEvents).toHaveLength(3);
    expect(statusEvents.every(event => event.actorUserId === identity.userId)).toBe(true);
    expect(statusEvents.some(event => event.visibility === "public")).toBe(true);

    const lateUpdate = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "A late update should not be accepted." }
    });
    expect(lateUpdate.status).toBe(409);
    expect(await lateUpdate.json()).toMatchObject({ error: "INCIDENT_ALREADY_RESOLVED" });
  });

  it("keeps viewers read-only for incident updates and status changes", async () => {
    const identity = await createIdentity("viewer");
    const incidentId = await createIncident(identity.organizationId);

    const note = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "Viewer write attempt." }
    });
    const status = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "identified" }
    });

    expect(note.status).toBe(403);
    expect(status.status).toBe(403);
  });

  it("does not allow a member to mutate another workspace's incident", async () => {
    const identity = await createIdentity("member");
    const foreign = await createIdentity("owner");
    const incidentId = await createIncident(foreign.organizationId);

    const note = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "Cross-tenant write attempt." }
    });
    const status = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "identified" }
    });

    expect(note.status).toBe(403);
    expect(status.status).toBe(403);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM incident_events WHERE incident_id = ?")
      .bind(incidentId).first<{ count: number }>();
    expect(count?.count).toBe(1);
  });

  it("rejects invalid transitions, unsafe messages and invalid visibility", async () => {
    const identity = await createIdentity("admin");
    const incidentId = await createIncident(identity.organizationId);

    const skippedState = await api("/v1/incidents/" + incidentId, {
      token: identity.sessionToken,
      method: "PATCH",
      body: { status: "resolved" }
    });
    const emptyMessage = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "   " }
    });
    const controlMessage = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "unsafe\u0000message" }
    });
    const invalidVisibility = await api("/v1/incidents/" + incidentId + "/updates", {
      token: identity.sessionToken,
      method: "POST",
      body: { message: "Valid note.", visibility: "everyone" }
    });

    expect(skippedState.status).toBe(409);
    expect(emptyMessage.status).toBe(400);
    expect(controlMessage.status).toBe(400);
    expect(invalidVisibility.status).toBe(400);
  });

  it("serializes concurrent transitions so only one event is appended", async () => {
    const identity = await createIdentity("owner");
    const incidentId = await createIncident(identity.organizationId);
    const requests = await Promise.all([
      api("/v1/incidents/" + incidentId, {
        token: identity.sessionToken,
        method: "PATCH",
        body: { status: "identified", message: "First operator update." }
      }),
      api("/v1/incidents/" + incidentId, {
        token: identity.sessionToken,
        method: "PATCH",
        body: { status: "identified", message: "Concurrent operator update." }
      })
    ]);

    expect(requests.filter(response => response.status === 200)).toHaveLength(1);
    expect(requests.filter(response => response.status === 409)).toHaveLength(1);
    const count = await env.DB.prepare("SELECT COUNT(*) AS count FROM incident_events WHERE incident_id = ? AND event_type = 'incident.status_changed'")
      .bind(incidentId).first<{ count: number }>();
    expect(count?.count).toBe(1);
  });
});
