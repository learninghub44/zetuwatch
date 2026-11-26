# ZetuWatch webhook delivery

## Current implementation and launch state

The integration branch now connects the incident-event D1 outbox to the dedicated authenticated Node probe-agent webhook operation. The Worker decrypts the endpoint destination and signing secret, constructs a stable event payload, signs the exact body with timestamped HMAC-SHA256, rechecks the endpoint and current lease immediately before the agent request, and settles the durable delivery/attempt rows.

The customer Alerts screen supports endpoint create, rename, enable/disable, secret rotation, removal, and per-endpoint delivery/attempt history. Activation is gated by explicit operator configuration and a successful decrypt/authentication check of the stored endpoint.

**Production delivery remains disabled by default.** `wrangler.toml` sets `WEBHOOKS_ENABLED = "false"`. No production secrets, agent deployment, DNS lookup, or customer webhook request has been configured or performed in this implementation run. Code and tests on an integration branch are not evidence of production readiness.

## Operator configuration

The Worker requires all of the following before an owner can enable an endpoint:

- `WEBHOOKS_ENABLED=true` as a non-secret Worker variable. The repository default is false.
- `WEBHOOK_ENCRYPTION_KEY`: 32 random bytes encoded as unpadded base64url (43 characters).
- `PROBE_AGENT_URL`: the trusted agent's HTTPS `/v1/probe` URL. The webhook client derives the dedicated `/v1/webhook` route from its origin.
- `PROBE_SHARED_SECRET`: the agent's shared HMAC secret, at least 32 bytes.

Generate a new encryption key locally:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Store secrets using the Cloudflare secret manager, not in `wrangler.toml`, `.dev.vars.example`, source files or commits:

```sh
npx wrangler secret put WEBHOOK_ENCRYPTION_KEY
npx wrangler secret put PROBE_SHARED_SECRET
```

Set `PROBE_AGENT_URL` as a Worker variable for the trusted agent URL, and set `WEBHOOKS_ENABLED=true` only after the agent is deployed and the full launch gates have passed. Do not enable the variable merely to test the UI. The existing `PROBES_ENABLED` switch is separate; webhook delivery can be configured without enabling customer monitor probes.

The `deliveryConfigured` API field means the operator variables and secret shapes are present and the agent URL passes local validation. It does not prove that the agent is reachable, its certificate is trusted, or a destination can be delivered to.

The deterministic encryption key in `vitest.config.mts` is test-only and must never be reused in a deployed environment. Master-key rotation is not implemented. The encryption version is recorded as 1; losing the key makes existing endpoint values unrecoverable.

## Endpoint API and customer controls

All routes require a verified browser session and organization membership. Read-only API keys are denied. Owners/admins may create, rename, enable/disable, rotate and remove endpoints. All workspace members may read safe endpoint metadata and delivery history.

- `GET /v1/organizations/{organizationId}/webhooks`: safe endpoint metadata and `deliveryConfigured`.
- `POST /v1/organizations/{organizationId}/webhooks`: create an HTTPS endpoint and return its new `whsec_` secret once. New endpoints are disabled.
- `PATCH /v1/organizations/{organizationId}/webhooks/{endpointId}`: rename with `{"name":"Production alerts"}`, or enable/disable with `{"enabled":true}` / `{"enabled":false}`.
- `POST /v1/organizations/{organizationId}/webhooks/{endpointId}/rotate`: replace the signing secret and return it once.
- `GET /v1/organizations/{organizationId}/webhooks/{endpointId}/deliveries?limit=25`: return up to 50 recent deliveries and their sanitized attempt records.
- `DELETE /v1/organizations/{organizationId}/webhooks/{endpointId}`: disable, cancel pending work and scrub encrypted destination/secret material while retaining an audit record.

The endpoint API accepts only syntactically valid HTTPS destinations without credentials, fragments, non-default ports, IP literals or obvious local/reserved suffixes. Creation and rotation do not resolve DNS or send a test request. Enabling additionally decrypts both stored values with tenant/endpoint/field-bound AAD, validates the normalized URL and destination hash, and validates the signing secret before changing the endpoint state. This is not DNS validation; every delivery attempt performs its own DNS and connection policy in the agent.

## Durable outbox, scheduling and retries

Migration `0011_webhook_delivery_outbox.sql` creates one delivery per incident-event/endpoint pair. A D1 trigger enqueues only enabled, non-deleted endpoints in the incident's workspace. Internal customer-authored notes and internal status changes are excluded. Tenant guards reject mismatched endpoint, organization, incident and event references. Outbox rows contain references only, never destination URLs or signing secrets.

The one-minute Worker Cron handler runs bounded email notifications, then webhook delivery, then monitor probes sequentially. The webhook dispatcher claims at most 3 deliveries per invocation and runs at most 2 agent requests concurrently. Each claim has a 90-second lease; the worker uses a live clock for preflight and settlement so an invocation's original scheduled timestamp cannot make an expired lease appear valid. The dedicated agent operation has a 15-second total destination deadline and the Worker request is capped at 20 seconds.

There are at most 8 attempts. Retry delays are 30 seconds, 2 minutes, 10 minutes, 30 minutes, 2 hours, 6 hours and 6 hours; the eighth attempt is terminal. A valid receiver `Retry-After` hint is honored up to 6 hours. Transient DNS, timeout, TLS, network, 429, 5xx and agent-availability failures are retried. Destination-policy rejection, redirects and ordinary 4xx responses are terminal. Endpoint decryption failures are retried so an operator can restore a temporarily misconfigured encryption key before the bounded retry budget is exhausted. Completed attempt rows are immutable. Endpoint disable/removal cancels queued work and closes a started attempt; a request already opened over the network cannot be recalled.

Delivery is **at-least-once**, not exactly-once. If a receiver processes a request but the response is lost, ZetuWatch may retry it. The stable event ID must be durably deduplicated by the receiver.

## Signed payload contract

The Worker sends a JSON payload with:

- `eventId`: stable incident-event ID for receiver deduplication.
- `type`: `incident.opened`, `incident.monitoring`, `incident.resolved`, `incident.reopened`, `incident.status_changed` or `incident.update`.
- `createdAt`: normalized ISO-8601 event timestamp.
- `data.workspace.name`, `data.monitor.name` and `data.incident.id/status`.
- The event message only when the source timeline event is explicitly public. Incident summaries are not included because they are not a separately governed public field.

The payload excludes the monitor target URL, response body, request headers, credentials, private incident notes and internal update text. The body is bounded to 256 KiB.

The customer request carries:

- `X-ZetuWatch-Event-Id: <eventId>`
- `X-ZetuWatch-Signature: t=<unix-seconds>,v1=<64 lowercase hex characters>`

The HMAC-SHA256 input is the exact UTF-8 request body prefixed by `<unix-timestamp-seconds>.`. Receivers must verify the raw bytes before JSON parsing, enforce a short timestamp window (five minutes by default), compare signatures in constant time, and durably deduplicate `eventId`. Timestamp validation alone does not prevent replay within the accepted window.

## Egress security boundary

The Worker never calls ordinary `fetch(customerUrl)`. It submits one strict job to the separate authenticated `POST /v1/webhook` agent operation. The agent:

- revalidates HTTPS/default-port destination syntax on every attempt;
- rejects IP literals, credentials, fragments, localhost/metadata names and local/special-use suffixes;
- resolves all A/AAAA answers on every attempt and rejects empty, malformed, excessive or mixed public/private answer sets;
- pins the selected public address through the socket lookup while preserving the original hostname for TLS SNI and certificate verification;
- requires normal certificate verification and never follows redirects;
- bounds DNS to 2.5 seconds, total delivery to 15 seconds, request payload to 256 KiB, response headers to 16 KiB and discarded response body to 8 KiB;
- returns only a normalized status/error/retry hint, not the receiver's body or redirect location.

The Worker rechecks that the delivery lease is still current, the endpoint remains enabled/non-deleted, and the encrypted destination/secret/version have not changed immediately before the agent request. If the endpoint is disabled during an in-flight request, the D1 trigger cancels the row and stale settlement is rejected; the already-open network request cannot be recalled.

The agent's nonce replay cache is process-local. Multi-instance agent operation still requires a shared durable replay store or a verified single-instance deployment policy.

## Verification status

Added tests:

- `tests/webhook-dispatch.integration.test.ts`: signed exact-body success, public/internal payload filtering, transient retry scheduling, endpoint-disable during an in-flight request, and explicit operator gate.
- `tests/webhook-endpoints.integration.test.ts`: owner/admin activation policy, disabled-by-default behavior, tenant-scoped delivery history and attempt metadata without secret leakage.
- Existing Node agent tests cover URL/IP policy, mixed DNS answers, pinned lookup/SNI/TLS options, redirects, request/response limits, Retry-After, timeout handling and Worker-to-agent authentication.

The new Worker/D1 dispatcher and API-history integration tests have been committed but have not yet run through the repository's pinned TypeScript 5.9.3/Vitest CI. No production TLS handshake, public DNS rebinding test, live receiver delivery, or Worker-to-agent-to-D1 production-like test has been performed. Keep `WEBHOOKS_ENABLED=false` and all endpoints disabled until those checks pass.
