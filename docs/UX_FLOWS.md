# ZetuWatch UX and Interaction Blueprint

## Visual direction
A calm, precise operations product. Use warm near-white surfaces, deep ink text, restrained green for healthy states, amber for degraded states and red only for incidents. Avoid decorative gradients, oversized empty panels, emoji icons and blue/purple dashboard clichés. Use a legible sans-serif type system (Inter or DM Sans), consistent 8px spacing rhythm, subtle borders and purposeful density.

## Shared application shell
- Left navigation on desktop: Overview, Monitors, Incidents, Status pages, Analytics, Alerts, Team, Billing and Settings.
- On narrow screens use a compact top bar and accessible navigation drawer.
- Organization switcher and current workspace are always visible.
- Top-right: search/command menu, help, notifications and account menu.
- Page header: breadcrumb, clear title, one primary action and contextual secondary actions.
- Content width should use the available monitor space without stretching text excessively.
- Tables need sticky headers when long, meaningful filters, sorting, pagination, row actions and mobile alternatives.
- Every page needs loading skeleton, empty state, error state, permission-denied state and populated state.

## First-run checklist
1. Verify email.
2. Add first monitor.
3. Confirm first successful check.
4. Configure an alert destination.
5. Invite a teammate.
6. Publish a status page.

Checklist is contextual and dismissible. Each item links directly to the relevant task and reports completion from persisted state, not browser-only flags.

## Add-monitor wizard
Step 1 — Target
- Name (suggest hostname, editable)
- URL
- Monitor type selector with HTTP/HTTPS and API available at launch
- Validate scheme, hostname and port; explain blocked targets without exposing internal network details

Step 2 — Check behavior
- Method, interval, timeout, expected status
- Optional keyword/JSON assertion
- Redirect behavior explained
- Advanced options collapsed by default

Step 3 — Alerts
- Choose verified email or configured webhook
- Explain incident confirmation and recovery alerts
- Allow skipping and returning later

Step 4 — Review
- Human-readable summary, limits impact and next scheduled check
- Run test now; show result, response code and latency
- Confirm and create

After save: take user to monitor detail with live/pending state; do not fabricate a successful result if scheduler has not run.

## Monitor detail
- Current state, target, interval, last/next check and actions.
- Time-range selector and response-time chart.
- Check history with error categories and expandable sanitized diagnostics.
- Incidents and maintenance history.
- Settings, alert overrides and danger zone separated from ordinary actions.

## Incident handling
- Incident detail opens with severity/state, affected monitors and start time.
- Timeline entries show actor, state transition and update text.
- Actions: acknowledge, update status, add customer-facing update, resolve.
- Public update preview shows exactly what status-page subscribers will see.
- Resolved incidents remain searchable and exportable.

## Status page builder
- Guided setup: page name, URL slug, logo/theme, components, visibility and publish.
- Draft preview is distinct from published page.
- Component groups can be reordered accessibly.
- Custom domain setup includes DNS instructions and verification state.
- Subscribers must explicitly consent; provide unsubscribe path.

## Billing journey
- Usage page always explains current usage against plan limits.
- Upgrade screen compares actual limits, not vague feature labels.
- Checkout confirms amount, currency, billing period and renewal model before redirect.
- Payment pending, success, failure, cancellation, duplicate callback and refund states are handled.
- Never grant paid entitlements solely from a browser redirect; verify signed provider callbacks server-side.

## Settings and account safety
- Profile, email verification, password/session controls, organization details, members/roles, API keys, webhooks, export and deletion.
- API key creation reveals the secret once; store only a hash and show last-used metadata.
- Invitations expire and are single-use.
- Role changes and member removal require confirmation and audit events.

## Content and interaction rules
- Use plain language: “We couldn't reach this address” rather than leaking network exceptions.
- Show exact timestamps with timezone.
- Explain why an action is disabled and how to resolve it.
- Destructive actions require confirmation and clear consequences.
- Never use color alone to communicate health; include text and iconography.
- Avoid empty dashboard cards; guide the user to the next useful action.
- Keep forms short, group related fields, preserve input on errors and show validation beside the field.
