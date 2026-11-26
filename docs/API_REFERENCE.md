# API reference — current development endpoints

Base URL is the deployed Worker origin. JSON request bodies use `Content-Type: application/json`. Browser calls must use `credentials: "include"` so the HttpOnly session cookie is sent.

## Authentication

See [AUTH_SETUP.md](AUTH_SETUP.md) for account security and provider setup.

- `POST /auth/register` — `{ name, email, password, workspaceName? }`. Password must be 12–128 characters. A new account returns 201; an existing address receives a generic 202 response to reduce account enumeration.
- `POST /auth/verify` — `{ token }`. Consumes a one-use email verification token.
- `POST /auth/resend-verification` — `{ email }`. Generic response regardless of account state.
- `POST /auth/login` — `{ email, password }`. Sets an HttpOnly session cookie.
- `POST /auth/logout` — revokes the current session.
- `GET /auth/me` — returns the signed-in user and workspace memberships.
- `POST /auth/password-reset/request` — `{ email }`. Always returns a generic 202 response.
- `POST /auth/password-reset/confirm` — `{ token, password }`. Consumes the one-use reset token and revokes all existing sessions.

## Workspace API keys

API keys are created, listed and revoked by workspace owners/admins using a verified session. They are scoped to one workspace, expire after 30, 90 or 365 days, and are read-only. A workspace can have at most 10 active keys.

- `GET /v1/organizations/<organization-id>/api-keys` — list safe key metadata. The secret and hash are never returned.
- `POST /v1/organizations/<organization-id>/api-keys` — create a key with `{ name, expiresInDays: 30|90|365 }`. The response includes `secret` exactly once. Store it in a server-side secret manager; it cannot be retrieved later.
- `DELETE /v1/organizations/<organization-id>/api-keys/<key-id>` — revoke a key immediately. Repeated revocation is idempotent.
- Use `Authorization: Bearer zw_live_...` on supported read endpoints: monitor list/detail/check history and incident list/detail. Keys cannot create, update, pause, resume or delete monitors, change incidents, access authentication or team endpoints, or view internal incident timeline notes.

An explicit `Authorization` header takes precedence over a session cookie; an invalid bearer credential never falls back to a valid cookie. The key is stored as a SHA-256 hash of a cryptographically random 256-bit secret. Authentication requires the creator to remain a verified owner/admin of the key's workspace; demotion/removal therefore disables the key. `last_used_at` is updated on successful authentication. Do not put API keys in browser code, URLs, logs or source control.

## Status pages

Status pages are workspace-owned public summaries. All administration endpoints require a verified browser session; read-only API keys cannot access status-page administration.

- `GET /v1/organizations/<organization-id>/status-pages` — list non-archived pages for a workspace. Any workspace member may read.
- `POST /v1/organizations/<organization-id>/status-pages` — owner/admin only. Body: `{ name, slug, description?, monitorIds: string[] }`. Names are 2–80 characters, descriptions up to 240 characters, slugs are globally unique lowercase URL-safe values (3–48 characters), and at most 50 live monitors may be attached.
- `GET /v1/status-pages/<page-id>` — retrieve page configuration and live component names/types for a workspace member.
- `PATCH /v1/status-pages/<page-id>` — owner/admin only. Updates name, slug, description and optionally the ordered `monitorIds` list. A published page cannot be edited to remove its final component.
- `POST /v1/status-pages/<page-id>/publish` — owner/admin only, body `{ published: boolean }`. Publishing requires at least one non-deleted monitor. Unpublishing immediately makes the public URL return 404.
- `DELETE /v1/status-pages/<page-id>` — owner/admin only; archives and unpublishes the page without deleting its audit record or component history.
- `GET /public/status-pages/<slug>` — unauthenticated read of a published page only. Returns page name/description, component names/types and customer-visible incident updates. It never returns monitor IDs, raw target URLs, workspace identifiers or internal incident notes.

The static public renderer is `status.html?slug=<slug>`. It uses text-only DOM rendering and does not require a session. Because scheduled monitoring is still disabled, the public API always reports `monitoringEnabled: false` and `overallStatus: "unknown"`; components are not labelled operational and no uptime or latency is fabricated. Only timeline events explicitly marked `public` are returned. Internal notes are never included.

SQLite triggers enforce same-workspace component membership even if a future code path bypasses the API. If a monitor is soft-deleted and was the last live component on a published page, the page is automatically unpublished. Slugs remain reserved after archive to avoid a previously shared URL silently pointing to a different page.

## Workspace monitor configuration

All monitor endpoints require a verified signed-in session and an organization membership.

- `GET /v1/monitors?organizationId=<id>` — list up to 100 monitors in the selected workspace. Each row includes a state derived from persisted checks and any unresolved incident.
- `POST /v1/monitors` — create a monitor. Body: `{ organizationId, name, targetUrl, monitorType: "http"|"api", method: "GET"|"HEAD", expectedStatus, intervalSeconds, timeoutMs }`. It stores the configuration and makes the monitor due; it does not synchronously probe the target.
- `GET /v1/monitors/<uuid>` — retrieve a monitor and its derived state.
- `GET /v1/monitors/<uuid>/checks` — retrieve up to 100 stored checks, newest first. Each row includes its timestamp, pass/fail result, HTTP status, response time and error category. The response includes the current `executionEnabled` configuration signal; this read never triggers a probe.
- `PATCH /v1/monitors/<uuid>` — update name, target URL, method, expected status, interval or timeout.
- `POST /v1/monitors/<uuid>/pause` and `POST /v1/monitors/<uuid>/resume` — pause or resume future scheduling. Owners/admins/members may manage monitor state; viewers are read-only. Actions are idempotent, clear any active lease, and resume makes the monitor due. Both return the current `executionEnabled` configuration signal; neither sends a probe synchronously.
- `DELETE /v1/monitors/<uuid>` — owner/admin only; soft-deletes and disables the monitor, removes it from monitor list/detail APIs, and retains check, incident and timeline rows. There is no hard-delete endpoint yet.

Viewers can read. Members/admins/owners can create and update. Only owners/admins can delete. Every query is scoped through the monitor's organization membership; never trust an organization ID supplied by a client without checking membership.


## Organization team management

All team endpoints require a verified signed-in session. The caller must already belong to the requested organization. Invitation creation additionally requires the Resend provider to be configured; invitation tokens are stored only as SHA-256 hashes and expire after seven days.

- `GET /v1/organizations/<organization-id>/members` — list members and their roles.
- `PATCH /v1/organizations/<organization-id>/members/<user-id>` — change a member role with body `{ role: "admin"|"member"|"viewer" }`. Only owners can grant or remove administrator privileges; admins may assign member/viewer.
- `DELETE /v1/organizations/<organization-id>/members/<user-id>` — remove a member. Members may remove themselves, admins may remove members/viewers, and owners may remove non-owners. The last owner cannot be demoted or removed.
- `GET /v1/organizations/<organization-id>/invitations` — list pending, unexpired invitations (owner/admin).
- `POST /v1/organizations/<organization-id>/invitations` — invite with body `{ email, role? }`. Only owner/admin; admins can invite member/viewer. Email delivery must succeed or the pending invitation is deleted.
- `POST /v1/invitations/accept` — accept with body `{ token }`. The signed-in verified account email must exactly match the invited email.

Role changes, removals, invitation creation and acceptance write audit events. These endpoints and an initial responsive workspace team screen are implemented. API integration tests, invitation acceptance browser testing, and the complete team-management UI states are still outstanding. Do not consider team management launch-complete until those tests pass.

## Incident reads and customer actions

All incident reads require a verified signed-in session and membership in the incident's owning workspace. Members, admins, owners and viewers may read incidents. Mutations require an owner, admin or member role; viewers are read-only.

- `GET /v1/incidents?organizationId=<id>` — list up to 100 incidents for the selected workspace, newest first.
- `GET /v1/incidents/<uuid>` — retrieve an incident with its ordered timeline. Each event includes its visibility and, when the account still exists, the actor's display name.
- `PATCH /v1/incidents/<uuid>` — advance or regress an active incident using `{ status, message?, visibility? }`. Supported transitions are investigating → identified, identified → investigating/monitoring, and monitoring → identified/resolved. A resolved incident is terminal. Status changes and their timeline/audit events are written in one D1 batch; a concurrent stale transition receives 409.
- `POST /v1/incidents/<uuid>/updates` — append a workspace note using `{ message, visibility? }`. Messages are limited to 500 characters and control characters are rejected. Status and note writes are separately rate-limited to 30 requests per 15 minutes per source IP. Updates cannot be added after resolution.

Timeline visibility is `internal` by default or `public` when explicitly selected. Public visibility is stored for a future status-page publisher; these updates are not currently published to an external page. The database trigger blocks in-place timeline event updates, and the new API only inserts events. Monitor deletion now soft-deletes and disables the monitor while retaining check, incident and timeline rows. Hard-purge/retention and account-deletion workflows are not yet implemented.

## Monitor detail and check history

The workspace monitor list provides a **View** action that opens a detail panel. It loads the tenant-authorized monitor record and persisted check history, and renders stored values using text-only DOM nodes. State labels are derived from the latest persisted check and unresolved incident: paused, execution disabled, awaiting first check, healthy, suspect, check delayed, down or recovering. An unresolved incident remains down/recovering even if probe dispatch is later disabled; other enabled monitors show execution disabled rather than a stale healthy state. When `next_check_at` is overdue by more than the greater of two minutes or two configured intervals, the API returns `check_delayed` instead of presenting an old successful result as current health. This is a scheduler-freshness warning, not a confirmed outage. An empty history is explicitly shown as no checks recorded; the UI does not invent status, uptime or latency values. Refreshing history only reads the API and never sends a request to the monitored target.

## Monitor execution status

The API returns `executionEnabled: true` only when the operator explicitly sets `PROBES_ENABLED=true`, supplies a valid HTTPS `PROBE_AGENT_URL` ending in `/v1/probe`, and provides a `PROBE_SHARED_SECRET` of at least 32 bytes. Otherwise it returns false and a disabled-state note. This is a configuration signal, not proof that the external agent is reachable or that a target has passed a check. Monitor state is never inferred from configuration alone: before the first persisted result it remains awaiting first check; later states are derived from check history and unresolved incident status. Creating/updating/resuming a monitor changes its due time but does not synchronously send a probe. The one-minute Cron handler dispatches only when the operator gate and agent configuration are valid. The DNS-pinned probe agent and bounded D1 dispatcher are implemented on the integration branch, but full CI, live DNS/TLS verification, agent deployment and production-like Worker-to-agent-to-D1 verification remain launch gates. Keep `PROBES_ENABLED` unset until those gates pass.

## Error responses

Errors use JSON such as `{ "error": "UNAUTHENTICATED" }`. Common status codes: 400 invalid input, 401 no valid session, 403 insufficient membership/role, 404 missing resource, 405 unsupported method, 429 rate limit, and 503 unconfigured provider. Error messages must not include secrets, full response bodies or internal network details.


## Email notification channels and delivery history

All notification-management routes require a verified browser session and workspace membership. Read-only API keys are denied.

- `GET /v1/organizations/<organization-id>/notification-channels` — list up to 50 channels. Owners/admins see all workspace channels; members/viewers see only channels they created.
- `POST /v1/organizations/<organization-id>/notification-channels` — create an email channel with body `{ "channelType": "email" }`. The destination must be the signed-in user's own verified account email; arbitrary recipients and webhook destinations are rejected. Owners/admins/members may add their own address; viewers cannot.
- `PATCH /v1/organizations/<organization-id>/notification-channels/<channel-id>` — enable or disable with `{ "enabled": true|false }`. Owners/admins can manage all workspace channels; members can manage their own.
- `DELETE /v1/organizations/<organization-id>/notification-channels/<channel-id>` — remove a channel. Owners/admins can remove any workspace channel; members can remove their own. Pending deliveries are cancelled.
- `GET /v1/organizations/<organization-id>/notification-deliveries` — return the latest 100 delivery records. Owners/admins see all workspace deliveries; members/viewers see only deliveries for their own channels. The response includes event type, recipient, monitor name, status, attempt count, sanitized error code and delivery/retry timestamps.

Incident lifecycle events and customer-authored incident updates are inserted into a durable D1 outbox in the same database batch as the timeline event. The one-minute Cron Trigger dispatches at most five queued deliveries per invocation. Claims use 90-second leases; the dispatcher retries transient provider/network failures at 30 seconds, 2 minutes, 10 minutes, 1 hour and 6 hours, then marks the sixth attempt failed. Provider `Retry-After` values are honored up to six hours. A stable event/channel idempotency key is sent to Resend on every attempt.

Configure `RESEND_API_KEY` and `EMAIL_FROM` in the Worker environment and set `PUBLIC_APP_URL` to the public HTTPS application origin. If the provider credentials or sender are absent, the scheduled dispatcher skips sending and leaves queued rows available for a later run. See [EMAIL_NOTIFICATIONS.md](EMAIL_NOTIFICATIONS.md) for setup and operational limitations.

Disabling/removing a channel cancels queued work. It cannot recall an email already accepted by the provider. Delivery records are operational logs, not proof that the recipient's mailbox accepted or displayed a message.


Delivery history retains the channel creator identifier independently of the channel row. Removing a channel sets the delivery's channel reference to null but does not erase the delivery record; the original member can still inspect their own retained log while they remain in the workspace. Workspace owners/admins can inspect all retained delivery records.


## Encrypted webhook endpoint configuration and delivery

All routes require a verified browser session and organization membership. Read-only API keys are denied. Owners/admins may create, rename, enable/disable, rotate and remove endpoints; all workspace members may read safe metadata and delivery history.

- `GET /v1/organizations/{organizationId}/webhooks` — returns endpoint ID, name, destination hostname, secret suffix, enabled state, timestamps and `deliveryConfigured`. It never returns the URL, ciphertext or secret. `deliveryConfigured` describes operator configuration only; it does not prove agent reachability or receiver delivery.
- `POST /v1/organizations/{organizationId}/webhooks` — body `{"name":"Production alerts","url":"https://hooks.example.com/events"}`. Returns a new `whsec_` secret once; new endpoints are disabled.
- `PATCH /v1/organizations/{organizationId}/webhooks/{endpointId}` — rename with `{"name":"Updated name"}`, enable with `{"enabled":true}`, or disable with `{"enabled":false}`. Enabling requires `WEBHOOKS_ENABLED=true`, valid operator key/agent configuration, and successful decryption/authentication of the stored endpoint values. Disable remains available when operator delivery is unavailable.
- `POST /v1/organizations/{organizationId}/webhooks/{endpointId}/rotate` — returns a replacement signing secret once.
- `GET /v1/organizations/{organizationId}/webhooks/{endpointId}/deliveries?limit=25` — returns up to 50 recent delivery records with attempt number, status, response status, sanitized error code and timestamps. It never returns payloads, endpoint URLs, ciphertext or secrets.
- `DELETE /v1/organizations/{organizationId}/webhooks/{endpointId}` — scrubs encrypted URL/secret material, disables the endpoint, cancels queued deliveries and retains the audit event.

A workspace may configure up to 10 active endpoint records. URL validation at creation is syntactic only; it does not resolve DNS. No test request or DNS query is made during creation, rename, rotation or enablement. Each actual delivery resolves and pins public A/AAAA answers in the dedicated agent.

The Worker requires a 32-byte base64url `WEBHOOK_ENCRYPTION_KEY`, a trusted HTTPS `PROBE_AGENT_URL` ending in `/v1/probe`, and a `PROBE_SHARED_SECRET` of at least 32 bytes. The non-secret `WEBHOOKS_ENABLED` variable defaults to `false` in `wrangler.toml`. The one-minute scheduled handler claims at most three webhook deliveries with at most two concurrent agent requests. Delivery uses 90-second leases and up to eight attempts with bounded backoff. It is at-least-once; receivers must verify `X-ZetuWatch-Signature` over the exact raw body and durably deduplicate `eventId`.

See [WEBHOOK_DELIVERY.md](WEBHOOK_DELIVERY.md) for the payload contract, egress model, operator setup and outstanding verification gates.
