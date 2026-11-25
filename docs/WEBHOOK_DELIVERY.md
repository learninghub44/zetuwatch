# ZetuWatch webhook endpoint configuration and outbox

## Current scope

The workspace Alerts screen can store HTTPS webhook endpoint configuration and generate a per-endpoint signing secret. The endpoint URL and signing secret are encrypted before they are written to D1. The secret is returned once on creation or rotation; list responses never include the URL, ciphertext or signing secret.

A durable event outbox and per-attempt history are now implemented in the integration branch. A database trigger creates one queued delivery for each enabled endpoint when an eligible incident timeline event is inserted. The trigger excludes internal customer-authored notes and internal status changes, enforces workspace/incident/event ownership, and uses a unique event/endpoint key for idempotency. The outbox stores references only; it does not copy destination URLs or signing secrets.

**Outbound webhook delivery is still disabled.** Endpoint creation does not send a test request, DNS query or HTTP request. The public API keeps endpoints disabled; no endpoint activation route or outbound dispatcher is enabled yet. Do not infer delivery from the endpoint appearing in the list or from an outbox row.

## API

All endpoint configuration routes require a verified browser session and membership in the organization. API keys are rejected.

- `GET /v1/organizations/{organizationId}/webhooks`: list safe endpoint metadata. All workspace members may read the metadata.
- `POST /v1/organizations/{organizationId}/webhooks`: owner/admin creates an endpoint. The response includes its secret exactly once.
- `PATCH /v1/organizations/{organizationId}/webhooks/{endpointId}`: owner/admin changes the display name.
- `POST /v1/organizations/{organizationId}/webhooks/{endpointId}/rotate`: owner/admin rotates the secret and receives the replacement exactly once.
- `DELETE /v1/organizations/{organizationId}/webhooks/{endpointId}`: owner/admin disables and scrubs encrypted URL/secret material.

The API caps active endpoints at 10 per workspace. It validates HTTPS syntax, rejects credentials, fragments, non-default ports, IP literals and obvious local/reserved host suffixes. This is a syntax gate only: it does not prove that a hostname resolves to public addresses.

## Encryption

The Worker requires a 32-byte base64url `WEBHOOK_ENCRYPTION_KEY` (43 characters without padding). Generate one locally with:

```sh
node -e "console.log(require('node:crypto').randomBytes(32).toString('base64url'))"
```

Configure it as a Cloudflare Worker secret, not a `vars` entry or committed Wrangler value:

```sh
npx wrangler secret put WEBHOOK_ENCRYPTION_KEY
```

For local development, place a development-only value in the ignored `.dev.vars` file. Never reuse the test-only key from `vitest.config.mts`.

AES-256-GCM uses a fresh 96-bit nonce for each encrypted value and a 128-bit authentication tag. Additional authenticated data binds the ciphertext to the organization ID, endpoint ID, schema version and field purpose (`url` or `secret`). Swapping ciphertext between tenants, endpoints or fields therefore fails decryption.

The database records encryption key version 1. A master-key rotation procedure is not implemented yet. Before rotating the Worker secret, a future migration/tool must decrypt and re-encrypt every active endpoint with the new key. If the current key is lost, existing endpoint values cannot be recovered; delete and recreate endpoints after configuring a new key.

## Durable outbox and attempt history

Migration `0011_webhook_delivery_outbox.sql` adds:

- `webhook_deliveries`: one event/endpoint delivery record with queued/sent/failed/cancelled state, attempt count, next-attempt timestamp, expiring lease, response status and a redacted error code.
- `webhook_delivery_attempts`: one append-only completed record per claimed attempt. A started attempt becomes `abandoned` when its lease expires and another worker reclaims the delivery.
- An incident-event insert trigger that fans out only to enabled, non-deleted endpoints in the same workspace. Internal customer-authored notes and internal status changes are excluded.
- A tenant guard that rejects mismatched endpoint, organization, incident and event references.
- A unique event/endpoint constraint so repeated enqueue attempts cannot create duplicate deliveries.
- Disabling or removing an endpoint cancels queued deliveries, clears their leases and marks any started attempt as abandoned. A sender must still re-check endpoint state immediately before opening the outbound connection.

The claim/settlement module enforces a 1–10 batch limit, 30–300 second leases, eight maximum attempts and retry delays from 30 seconds up to a six-hour cap. Only the current unexpired lease can settle a delivery. These primitives are not yet called by a network dispatcher or scheduled handler.

## Outbound safety requirements

Before delivery can be enabled, every attempt must:

- decrypt the URL and secret only inside the trusted dispatcher;
- resolve A and AAAA records at delivery time and reject empty, malformed, oversized or mixed public/private answer sets;
- pin the selected validated address for the connection while retaining the original hostname for TLS SNI and certificate verification;
- disable redirects entirely (or independently validate, resolve and pin every hop before following it); never permit HTTPS downgrade;
- enforce HTTPS, default port, strict connect/total deadlines, bounded headers and a small response-body cap;
- sign the exact request bytes with timestamped HMAC-SHA256 and include a stable event ID;
- use durable leases, bounded retries, idempotency and per-attempt delivery logs;
- re-check endpoint enabled/deleted state immediately before network I/O.

Do not use ordinary `fetch(destination)` for customer-configured endpoints. The current probe agent accepts only normalized monitor jobs and must not be turned into a general-purpose proxy. Webhook delivery needs a separate narrowly-scoped authenticated operation with its own schema and outbound request policy.

## Signature format implemented for the future dispatcher

The shared HMAC primitive signs the exact UTF-8 body bytes using HMAC-SHA256 over:

`<unix-timestamp-seconds>.<raw-body>`

The future request header format is:

`X-ZetuWatch-Signature: t=<timestamp>,v1=<64 lowercase hex characters>`

Receivers must verify the raw body before JSON parsing, enforce a short timestamp tolerance (default five minutes), and deduplicate the stable event ID durably. A valid timestamped HMAC alone does not prevent replay within the allowed tolerance. The signing/verification primitive is unit-tested, but it is not yet wired to a network dispatcher and no signature header is currently sent.

## Verification

Unit tests cover AES-GCM round trips, authenticated tenant/endpoint/field context, tampering, invalid keys, secret generation, destination syntax rejection, exact-body HMAC signing and timestamp tolerance. D1 integration tests cover endpoint authorization, tenant isolation, encryption at rest, one-time secret responses, rotation, deletion, endpoint limits, outbox fan-out, public/internal event filtering, lease claim/reclaim, stale settlement rejection and attempt-log immutability.

These tests make no DNS or HTTP request. They verify endpoint configuration and durable outbox state only; outbound webhook delivery remains disabled and is not counted as complete.
