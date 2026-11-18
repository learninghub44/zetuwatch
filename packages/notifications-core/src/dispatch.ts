import {
  claimDueNotificationDeliveries,
  parseRetryAfter,
  settleNotificationDelivery,
  type NotificationDelivery
} from "./outbox";

export interface NotificationDispatchEnv {
  DB: D1Database;
  PUBLIC_APP_URL: string;
  RESEND_API_KEY?: string;
  EMAIL_FROM?: string;
}

interface DeliveryContext {
  organizationName: string;
  monitorName: string;
  incidentStatus: string;
  incidentSummary: string;
  eventType: string;
  eventMessage: string;
  recipientEmail: string;
  channelId: string;
  eventId: string;
}

export interface NotificationDispatchSummary {
  skipped: boolean;
  claimed: number;
  sent: number;
  retried: number;
  failed: number;
}

function escapeHtml(value: string): string {
  return value.replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export function buildIncidentEmail(context: DeliveryContext, appUrl: string): {
  subject: string;
  html: string;
  text: string;
} {
  const labels: Record<string, string> = {
    "incident.opened": "Incident opened",
    "incident.monitoring": "Recovery monitoring",
    "incident.resolved": "Incident resolved",
    "incident.reopened": "Incident reopened",
    "incident.status_changed": "Incident status updated",
    "incident.update": "Incident update"
  };
  const label = labels[context.eventType] ?? "Incident update";
  const subject = `[${context.organizationName}] ${label}: ${context.monitorName}`.slice(0, 180);
  const organization = escapeHtml(context.organizationName);
  const monitor = escapeHtml(context.monitorName);
  const status = escapeHtml(context.incidentStatus.replace(/_/g, " "));
  const summary = escapeHtml(context.incidentSummary);
  const message = escapeHtml(context.eventMessage);
  const link = appUrl.replace(/\/$/, "") + "/app.html#incidents";
  const safeLink = escapeHtml(link);
  const html = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#17211d">
    <p style="color:#16794b;font-weight:700">ZetuWatch</p>
    <p>${organization}</p>
    <h2 style="font-size:20px">${escapeHtml(label)}: ${monitor}</h2>
    <p><strong>Current incident state:</strong> ${status}</p>
    <p>${summary}</p>
    <p>${message}</p>
    <p><a href="${safeLink}">Open incident in ZetuWatch</a></p>
    <p style="color:#6d7972;font-size:12px">You receive this message because this verified email is subscribed to workspace incident alerts. You can disable or remove this channel from Workspace → Alerts.</p>
  </div>`;
  const text = [
    "ZetuWatch",
    organization.replace(/&amp;/g, "&"),
    `${label}: ${context.monitorName}`,
    `Current incident state: ${context.incidentStatus}`,
    context.incidentSummary,
    context.eventMessage,
    `Open incident in ZetuWatch: ${link}`,
    "You can disable or remove this channel from Workspace > Alerts."
  ].join("\n\n");
  return { subject, html, text };
}

async function loadDeliveryContext(
  env: NotificationDispatchEnv,
  delivery: NotificationDelivery,
  nowIso: string
): Promise<DeliveryContext | null> {
  if (!delivery.channelId || !delivery.eventId || !delivery.incidentId) return null;
  return env.DB.prepare(`
    SELECT
      o.name AS organizationName,
      m.name AS monitorName,
      i.status AS incidentStatus,
      i.summary AS incidentSummary,
      e.event_type AS eventType,
      e.message AS eventMessage,
      c.destination AS recipientEmail,
      c.id AS channelId,
      e.id AS eventId
    FROM notification_deliveries d
    JOIN notification_channels c
      ON c.id = d.channel_id AND c.organization_id = d.organization_id
      AND c.channel_type = 'email' AND c.is_enabled = 1 AND c.verified_at IS NOT NULL
    JOIN users u
      ON u.id = c.created_by AND u.email_verified_at IS NOT NULL
      AND lower(u.email) = lower(c.destination)
    JOIN organization_members om
      ON om.organization_id = c.organization_id AND om.user_id = u.id
    JOIN organizations o ON o.id = d.organization_id
    JOIN incidents i ON i.id = d.incident_id
    JOIN monitors m ON m.id = i.monitor_id AND m.organization_id = d.organization_id
    JOIN incident_events e ON e.id = d.event_id AND e.incident_id = i.id
    WHERE d.id = ? AND d.lease_token = ? AND d.status = 'queued'
      AND d.lease_until > ? AND d.recipient_email = c.destination
  `).bind(delivery.id, delivery.leaseToken, nowIso).first<DeliveryContext>();
}

async function readProviderErrorName(response: Response): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) return null;
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (length < 4096) {
      const { done, value } = await reader.read();
      if (done) break;
      const remaining = 4096 - length;
      const chunk = value.byteLength > remaining ? value.slice(0, remaining) : value;
      chunks.push(chunk);
      length += chunk.byteLength;
      if (chunk.byteLength < value.byteLength || length === 4096) {
        await reader.cancel().catch(() => undefined);
        break;
      }
    }
  } catch {
    return null;
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    const payload = JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>;
    const name = [payload.name, payload.error, payload.code]
      .find(value => typeof value === "string") as string | undefined;
    return name?.toLowerCase() ?? null;
  } catch {
    return null;
  }
}

async function sendWithResend(
  env: NotificationDispatchEnv,
  delivery: NotificationDelivery,
  context: DeliveryContext,
  fetcher: typeof fetch
): Promise<{ kind: "sent"; id: string } | { kind: "retry"; code: string; retryAfterSeconds: number | null } | { kind: "failed"; code: string }> {
  const email = buildIncidentEmail(context, env.PUBLIC_APP_URL);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetcher("https://api.resend.com/emails", {
      method: "POST",
      signal: controller.signal,
      headers: {
        authorization: `Bearer ${env.RESEND_API_KEY}`,
        "content-type": "application/json",
        "Idempotency-Key": `zetuwatch-${delivery.eventId}-${delivery.channelId}`,
        "User-Agent": "ZetuWatch/0.1"
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM,
        to: [context.recipientEmail],
        subject: email.subject,
        html: email.html,
        text: email.text
      })
    });

    if (response.ok) {
      const payload = await response.json().catch(() => null) as { id?: unknown } | null;
      if (typeof payload?.id !== "string" || !payload.id.trim()) {
        return { kind: "retry", code: "PROVIDER_RESPONSE_INVALID", retryAfterSeconds: null };
      }
      return { kind: "sent", id: payload.id };
    }
    if (response.status === 409) {
      const providerError = await readProviderErrorName(response);
      if (providerError === "concurrent_idempotent_requests") {
        return { kind: "retry", code: "PROVIDER_REQUEST_IN_PROGRESS", retryAfterSeconds: null };
      }
      return { kind: "failed", code: providerError === "invalid_idempotent_request"
        ? "PROVIDER_IDEMPOTENCY_CONFLICT" : "PROVIDER_CONFLICT" };
    }
    if (response.status === 429) {
      return { kind: "retry", code: "PROVIDER_RATE_LIMITED", retryAfterSeconds: parseRetryAfter(response.headers.get("retry-after")) };
    }
    if (response.status >= 500) return { kind: "retry", code: "PROVIDER_UNAVAILABLE", retryAfterSeconds: parseRetryAfter(response.headers.get("retry-after")) };
    return { kind: "failed", code: "PROVIDER_REJECTED" };
  } catch (error) {
    return {
      kind: "retry",
      code: error instanceof Error && error.name === "AbortError" ? "PROVIDER_TIMEOUT" : "PROVIDER_NETWORK_ERROR",
      retryAfterSeconds: null
    };
  } finally {
    clearTimeout(timeout);
  }
}

/**
 * Dispatch a small, leased batch of email notifications. It never executes
 * customer URLs and remains independent from the disabled monitor probe runner.
 */
export async function dispatchNotificationBatch(
  env: NotificationDispatchEnv,
  options: { now?: Date | string; limit?: number; fetcher?: typeof fetch } = {}
): Promise<NotificationDispatchSummary> {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM) {
    return { skipped: true, claimed: 0, sent: 0, retried: 0, failed: 0 };
  }
  const now = options.now ?? new Date();
  const fetcher = options.fetcher ?? fetch;
  const deliveries = await claimDueNotificationDeliveries(env.DB, {
    now,
    limit: options.limit ?? 5
  });
  const summary: NotificationDispatchSummary = {
    skipped: false, claimed: deliveries.length, sent: 0, retried: 0, failed: 0
  };

  for (const delivery of deliveries) {
    const context = await loadDeliveryContext(env, delivery, new Date().toISOString());
    if (!context) {
      const settled = await settleNotificationDelivery(env.DB, delivery, {
        kind: "failed", errorCode: "RECIPIENT_NOT_ELIGIBLE", now: new Date()
      });
      if (settled) summary.failed++;
      continue;
    }

    const result = await sendWithResend(env, delivery, context, fetcher);
    if (result.kind === "sent") {
      if (await settleNotificationDelivery(env.DB, delivery, {
        kind: "sent", providerMessageId: result.id, now: new Date()
      })) summary.sent++;
    } else if (result.kind === "retry") {
      if (await settleNotificationDelivery(env.DB, delivery, {
        kind: "retry", errorCode: result.code, retryAfterSeconds: result.retryAfterSeconds, now: new Date()
      })) {
        if (delivery.attemptCount >= 6) summary.failed++;
        else summary.retried++;
      }
    } else if (await settleNotificationDelivery(env.DB, delivery, {
      kind: "failed", errorCode: result.code, now: new Date()
    })) {
      summary.failed++;
    }
  }
  return summary;
}
