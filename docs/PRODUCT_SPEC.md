# ZetuWatch — Product Specification

**Product promise:** Know when a website or API becomes unavailable, understand what happened, and communicate service health clearly.

## Product principles
- Self-service first: a new customer can create an account, add a first monitor and receive a useful result without talking to sales.
- Honest reliability: show observed measurements, probe coverage and plan limits. Never imply that free-tier infrastructure provides an SLA.
- Secure by default: customer URLs are untrusted input; every tenant-owned record and action is authorized server-side.
- Progressive complexity: simple HTTP monitoring first; advanced API assertions, teams and integrations are discoverable when needed.
- Useful free tier: users can evaluate the core product before paying. Enforce transparent limits, never silently stop checks.

## Personas
1. Solo builder: wants to know if a personal site, portfolio or side project is reachable.
2. Developer: needs API checks, response assertions, latency history and webhook alerts.
3. Small business operator: wants simple monitoring, email notifications and a public status page.
4. Operations team: needs multiple projects, team roles, incident ownership, maintenance windows and audit history.

## Information architecture

### Public website
- Home: value proposition, product preview, core capabilities, trust/security explanation, pricing, FAQ and clear sign-up CTA.
- Features: website checks, API assertions, SSL/domain expiry, cron heartbeat, incident management, status pages and integrations.
- Pricing: free and paid plans, limits, billing frequency, add-ons and clear cancellation/renewal terms.
- Docs: quick start, monitor setup, API, webhooks, status pages, troubleshooting and security.
- Trust: service status, privacy, terms, data retention and security contact.
- Authentication: sign up, sign in, email verification, password reset and invitation acceptance.

### Authenticated application
- Overview: health summary, uptime, incidents, response-time trend, monitor status and setup checklist.
- Monitors: list, create wizard, details, edit, pause/resume, test, delete and bulk actions.
- Incidents: active/resolved, timeline, status updates, acknowledgement and resolution.
- Status pages: create, customize, component groups, publish, custom domain and subscriber management.
- Alerts: email destinations, webhook destinations, routing preferences, test delivery and delivery history.
- Analytics: uptime by period, latency percentiles, failure breakdown and downloadable reports.
- Team: members, invitations, roles, projects and access revocation.
- Settings: profile, organization, security, API keys, webhooks, data export and deletion.
- Billing: current plan, usage, invoices/receipts, payment method, renewals, cancellation and add-ons.
- Help: documentation, contact/support and service status.

### Internal admin
- Global service health and queue/scheduler status.
- Customer/org lookup with least-privilege access and audited support actions.
- Abuse reports, suspicious targets, rate limits and account suspension.
- Delivery failures, provider health, plan configuration and aggregate usage.
- Audit log and operational runbooks. No staff-visible secrets or unnecessary response bodies.

## Monitor types and staged delivery

### Launch-critical
- HTTP/HTTPS: URL, method, interval, timeout, expected status, redirect policy and optional keyword assertion.
- API: HTTP method, expected status, response-time threshold, safe custom headers and JSON-path assertion. Never expose stored secrets after creation.
- Check history: timestamp, status, latency, error category and region/probe identity.

### Follow-on
- SSL certificate expiry and hostname mismatch warnings.
- Domain expiry where a reliable registrar/WHOIS data source is available.
- Heartbeat/cron checks with generated secret ping URLs, grace period and missed-run incidents.
- TCP and DNS probes after safe egress controls and execution capacity exist.
- Multi-region checks only when real independent probe locations are deployed.

## Onboarding journey
1. Landing page → choose Get started.
2. Sign up with email; verify email before enabling notifications or publishing resources.
3. Create workspace: name, timezone (default inferred only as a suggestion), optional team.
4. Guided first monitor: paste URL, validate syntax and explain what will be checked.
5. Configure interval and expected response. Keep sensible defaults visible.
6. Run a safe one-time test; show what was tested and the observed result.
7. Create monitor and show the first check state, next scheduled check and alert setup prompt.
8. Verify notification email or configure webhook.
9. Invite teammates (skippable).
10. Publish a status page (skippable).
11. Show a concise checklist with completion progress; allow dismissal and later resume.

Onboarding must support back navigation, save-and-resume, keyboard navigation, inline validation, clear errors, loading states, empty states and a useful skip path. Do not force payment before a customer has experienced a successful check.

## Incident lifecycle
- Healthy → suspect after one failed probe → incident opened only after configured confirmation threshold.
- Incident states: investigating → identified → monitoring → resolved.
- Every state transition creates an immutable timeline event with actor and timestamp.
- Recovery requires successful follow-up checks according to policy.
- Flapping suppression, maintenance windows and deduplication prevent noisy alerts.
- Notification delivery is retried independently; provider failure never rolls back incident state.

## Notification channels
- Email: verify recipient, templates, unsubscribe/preferences and delivery records.
- Webhook: signed payloads, timestamp, replay protection, bounded retries and delivery log.
- SMS: later paid credits/add-on; show per-message pricing before purchase.
- Alert policies: trigger, recovery, reminder frequency, quiet hours and per-monitor overrides.

## Plans — proposed, not validated
- Free: 3 monitors, 5-minute interval, 7-day history, email alerts.
- Starter: KES 499/month, 15 monitors, 1-minute interval, 30-day history.
- Pro: KES 1,499/month, 75 monitors, 1-minute interval, 90-day history, team seats and status pages.
- Business: KES 3,499/month, 250 monitors, 1-minute interval, 1-year history, advanced roles and priority support.
- Enterprise: negotiated limits and support only when operationally supportable.

Prices and limits are hypotheses. Before enabling checkout, model Cloudflare quotas, email delivery costs, probe execution, abuse and support. Do not sell a check interval or SLA that the scheduler cannot reliably deliver. M-Pesa renewals may require customer-initiated renewal; do not promise automatic recurring M-Pesa debits unless the provider contract explicitly supports them.

## Non-functional requirements
- Tenant isolation on every query and mutation; composite foreign keys where practical.
- Authentication, email verification, secure sessions, CSRF protections where applicable, rate limits and audit logs.
- SSRF-resistant egress: DNS resolution and IP-range validation, rebinding resistance, redirect-hop validation and strict timeouts/size caps.
- Accessible WCAG 2.2 AA interface; responsive from small mobile screens to desktop.
- All timestamps stored in UTC and displayed in the user's chosen timezone.
- Data retention is explicit by plan; deletion/export flows are documented.
- Observability: structured redacted logs, scheduler lag, probe success, notification delivery and error budgets.
- Backups and restore drills before production customer data is accepted.

## Launch gates
A feature is not launch-ready until its API, UI, tests, authorization, abuse controls, documentation, monitoring and failure states exist. No mock data may be presented as live customer data. No payment, auth, email or DNS integration is considered configured until tested with real provider credentials in a controlled environment.
