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

- `GET /v1/monitors?organizationId=<id>` — list up to 100 monitors in the selected workspace.
- `POST /v1/monitors` — create a monitor. Body: `{ organizationId, name, targetUrl, monitorType: "http"|"api", method: "GET"|"HEAD", expectedStatus, intervalSeconds, timeoutMs }`.
- `GET /v1/monitors/<uuid>` — retrieve a monitor.
- `GET /v1/monitors/<uuid>/checks` — retrieve up to 100 stored checks, newest first. Each row includes its timestamp, pass/fail result, HTTP status, response time and error category. The response includes `executionEnabled: false`; this read does not trigger a probe.
- `PATCH /v1/monitors/<uuid>` — update name, target URL, method, expected status, interval or timeout.
- `POST /v1/monitors/<uuid>/pause` and `POST /v1/monitors/<uuid>/resume` — pause or resume future scheduling. Owners/admins/members may manage monitor state; viewers are read-only. Actions are idempotent, clear any active lease, and resume makes the monitor due. Both return `executionEnabled: false`; neither sends a probe while the secure runner is disabled.
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

The workspace monitor list provides a **View** action that opens a detail panel. It loads the tenant-authorized monitor record and persisted check history, and renders stored values using text-only DOM nodes. An empty history is explicitly shown as no checks recorded; the UI does not invent status, uptime or latency values. Refreshing history only reads the API and never sends a request to the monitored target.

## Monitor execution status

The current API deliberately returns `executionEnabled: false`. Creating a monitor stores its configuration but does not run a network request or schedule a check. Pausing and resuming only changes its persisted enabled state and due time; it does not activate execution. The current URL validator is preliminary and does not provide DNS resolution/pinning or DNS-rebinding protection. Do not enable scheduled probes until the egress security architecture is implemented and reviewed.

## Error responses

Errors use JSON such as `{ "error": "UNAUTHENTICATED" }`. Common status codes: 400 invalid input, 401 no valid session, 403 insufficient membership/role, 404 missing resource, 405 unsupported method, 429 rate limit, and 503 unconfigured provider. Error messages must not include secrets, full response bodies or internal network details.
