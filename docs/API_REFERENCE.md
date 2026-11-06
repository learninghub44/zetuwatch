# API reference — current development endpoints

Base URL is the deployed Worker origin. JSON request bodies use `Content-Type: application/json`. Browser calls must use `credentials: "include"` so the HttpOnly session cookie is sent.

## Authentication

See [AUTH_SETUP.md](AUTH_SETUP.md) for account security and provider setup.

- `POST /auth/register` — `{ name, email, password, workspaceName? }`. Password must be 12–128 characters. Returns a generic 202 response to avoid exposing account existence.
- `POST /auth/verify` — `{ token }`. Consumes a one-use email verification token.
- `POST /auth/resend-verification` — `{ email }`. Generic response regardless of account state.
- `POST /auth/login` — `{ email, password }`. Sets an HttpOnly session cookie.
- `POST /auth/logout` — revokes the current session.
- `GET /auth/me` — returns the signed-in user and workspace memberships.
- `POST /auth/password-reset/request` — `{ email }`. Always returns a generic 202 response.
- `POST /auth/password-reset/confirm` — `{ token, password }`. Consumes the one-use reset token and revokes all existing sessions.

## Workspace monitor configuration

All monitor endpoints require a verified signed-in session and an organization membership.

- `GET /v1/monitors?organizationId=<id>` — list up to 100 monitors in the selected workspace.
- `POST /v1/monitors` — create a monitor. Body: `{ organizationId, name, targetUrl, monitorType: "http"|"api", method: "GET"|"HEAD", expectedStatus, intervalSeconds, timeoutMs }`.
- `GET /v1/monitors/<uuid>` — retrieve a monitor.
- `GET /v1/monitors/<uuid>/checks` — retrieve up to 100 stored checks.
- `PATCH /v1/monitors/<uuid>` — update name, target URL, method, expected status, interval or timeout.
- `DELETE /v1/monitors/<uuid>` — owner/admin only; deletes the monitor and cascaded history.

Viewers can read. Members/admins/owners can create and update. Only owners/admins can delete. Every query is scoped through the monitor's organization membership; never trust an organization ID supplied by a client without checking membership.

## Monitor execution status

The current API deliberately returns `executionEnabled: false`. Creating a monitor stores its configuration but does not run a network request or schedule a check. The current URL validator is preliminary and does not provide DNS resolution/pinning or DNS-rebinding protection. Do not enable scheduled probes until the egress security architecture is implemented and reviewed.

## Error responses

Errors use JSON such as `{ "error": "UNAUTHENTICATED" }`. Common status codes: 400 invalid input, 401 no valid session, 403 insufficient membership/role, 404 missing resource, 405 unsupported method, 429 rate limit, and 503 unconfigured provider. Error messages must not include secrets, full response bodies or internal network details.
