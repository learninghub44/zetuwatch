import { describe, expect, it } from "vitest";
import { buildIncidentEmail } from "./dispatch";

describe("incident email rendering", () => {
  it("escapes workspace and incident text and does not include target URLs", () => {
    const email = buildIncidentEmail({
      organizationName: "Acme <script>alert(1)</script>",
      monitorName: "Public API & website",
      incidentStatus: "investigating",
      incidentSummary: "A service is unavailable",
      eventType: "incident.opened",
      eventMessage: "Response body <img src=x onerror=alert(1)>",
      recipientEmail: "ops@example.test",
      channelId: "channel-id",
      eventId: "event-id"
    }, "https://app.example.test");
    expect(email.subject).toContain("Incident opened");
    expect(email.html).not.toContain("<script>");
    expect(email.html).not.toContain("<img");
    expect(email.html).toContain("&lt;script&gt;");
    expect(email.html).toContain("https://app.example.test/app.html#incidents");
    expect(email.html).not.toContain("target_url");
  });
});


describe("notification email URL and header safety", () => {
  const context = {
    organizationName: "Acme",
    monitorName: "Payments API",
    incidentStatus: "investigating",
    incidentSummary: "Service unavailable",
    eventType: "incident.opened",
    eventMessage: "Incident opened",
    recipientEmail: "ops@example.test",
    channelId: "channel-id",
    eventId: "event-id"
  };

  it("rejects unsafe application link protocols and credential-bearing URLs", () => {
    expect(() => buildIncidentEmail(context, "javascript:alert(1)")).toThrow("NOTIFICATION_APP_URL_INVALID");
    expect(() => buildIncidentEmail(context, "https://user:pass@app.example.test")).toThrow("NOTIFICATION_APP_URL_INVALID");
  });

  it("removes control characters from the email subject", () => {
    const email = buildIncidentEmail({
      ...context,
      organizationName: "Acme\r\nBcc: attacker@example.test"
    }, "https://app.example.test");
    expect(email.subject).not.toMatch(/[\r\n]/);
  });
});
