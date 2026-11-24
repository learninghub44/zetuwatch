# ZetuWatch webhook endpoint configuration

## Current scope

The workspace Alerts screen can store HTTPS webhook endpoint configuration and generate a per-endpoint signing secret. The endpoint URL and signing secret are encrypted before they are written to D1. The secret is returned once on creation or rotation; list responses never include the URL, ciphertext or signing secret.

**Outbound webhook delivery is not enabled.** Creating an endpoint does not send a test request, DNS query or HTTP request. Endpoints remain disabled until a reviewed DNS-pinned outbound transport and durable webhook outbox/dispatcher have passed their security and integration tests. Do not infer delivery from the endpoint appearing in the list.

## API

All routes require a verified browser session and membership in the organization. API keys are rejected.

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

## Outbound safety requirements

When delivery is implemented, every attempt must:
- decrypt the URL and secret only inside the trusted dispatcher;
- resolve A and AAAA records at delivery time and reject mixed public/private answers;
- pin the selected validated address for the connection while retaining the original hostname for TLS SNI/certificate validation;
- disable redirects or independently validate, resolve and pin every redirect hop;
- reject HTTPS downgrade, non-default ports, private/reserved addresses and DNS rebinding;
- enforce strict connect/total deadlines, bounded headers and a small response-body cap;
- sign the exact request bytes with timestamped HMAC-SHA256 and a stable event ID;
- use durable leases, bounded retries, idempotency and delivery logs.

Do not use ordinary `fetch(destination)` for customer-configured endpoints. The current probe agent accepts only normalized monitor jobs and must not be turned into a general-purpose proxy.

## Verification

Unit tests cover AES-GCM round trips, authenticated tenant/endpoint/field context, tampering, invalid keys, secret generation and destination syntax rejection. D1 integration tests cover endpoint authorization, tenant isolation, encryption at rest, one-time secret responses, rotation, deletion and limits. These tests do not send network requests or claim that outbound delivery is ready.

## Signature format implemented for the future dispatcher

The shared HMAC primitive signs the exact UTF-8 body bytes using HMAC-SHA256 over:

`<unix-timestamp-seconds>.<raw-body>`

The future request header format is:

`X-ZetuWatch-Signature: t=<timestamp>,v1=<64 lowercase hex characters>`

Receivers must verify the raw body before JSON parsing, enforce a short timestamp tolerance (default five minutes), and deduplicate the stable event ID durably. A valid timestamped HMAC alone does not prevent replay within the allowed tolerance. The signing/verification primitive is unit-tested, but it is not yet wired to a network dispatcher and no signature header is currently sent.
