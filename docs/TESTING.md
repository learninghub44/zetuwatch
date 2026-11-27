# Testing and local verification

ZetuWatch uses Vitest for unit tests and Cloudflare's Workers Vitest integration for API tests that need the real Workers runtime and an isolated local D1 database.

## Requirements

- Node.js 22.12 or newer
- npm
- Dependencies installed from the pinned versions in `package.json`

The test-only `@cloudflare/vitest-plugin` dependency is MIT-licensed. It runs tests locally in `workerd`/Miniflare; it does not create or access a Cloudflare account resource.

## Commands

```sh
npm install
npm run typecheck
npm run check:inline-js
npm test
npm run test:integration
python scripts/check-migrations.py
```

The integration suite loads the repository's numbered SQL migrations into an isolated D1 database before the tests run. It seeds disposable identities, organizations, sessions and monitors in that local test database only.

## Authentication integration coverage (1 D1-backed test)

- Registration creates the user, workspace, owner membership and verification token.
- The verification email is captured by a test-only `fetch` stub; no real email is sent.
- Unverified login is rejected, the verification token is single-use, and verified login creates a session.
- The authenticated profile returns the newly created workspace.
- Password reset consumes its token once, revokes existing sessions, rejects the old password and accepts the new password.

The Resend endpoint and test-only API key are inert fixtures. The Worker test runtime intercepts the outbound `fetch`; these tests do not contact Resend.

## API integration coverage (18 D1-backed tests)

- Missing sessions are rejected.
- Organization-scoped monitor listing rejects users outside the requested organization.
- Monitor detail and check-history reads reject cross-tenant IDs.
- Workspace viewers can read persisted in-tenant check history; the response is newest-first and explicitly reports that scheduled execution is disabled.
- Owner deletion soft-deletes and disables a monitor, hides it from monitor routes, and retains check, incident and timeline records.
- Monitor creation cannot target an organization without membership.
- Members can create/read their own monitors but cannot delete them.
- Viewers can read but cannot create or update monitors.
- Owners/admins/members can pause and resume monitors; pause clears active leases, resume makes a monitor due, repeated actions are idempotent, and viewers, foreign tenants and archived monitors are rejected.
- Team membership cannot be read across tenant boundaries.
- A team invitation is consumed at most once when two acceptance requests race; only one membership and one acceptance audit event are created.
- Concurrent owner demotions cannot remove the final workspace owner.
- Incident lists require workspace membership and return only incidents belonging to that tenant.
- Incident detail and timeline reads reject a foreign-tenant incident ID.

The latest verified CI suite passed 115 tests across 13 files in [GitHub Actions run #175](https://github.com/learninghub44/zetuwatch/actions/runs/43171922270) on commit `a6cac79dcd3ccc2865629d93829d6e5cb0a782e8`. These tests verify Worker routes and scheduler/incident persistence against D1's SQLite-compatible runtime. They do not replace production D1 verification, browser end-to-end tests, provider delivery tests or a security review of outbound network execution. No scheduled probes are enabled by this test setup.


## Monitor control integration coverage (5 D1-backed tests)

- Owners can pause a monitor, clear its outstanding lease and create one audit event; repeated pause requests do not duplicate the audit event.
- Members can resume a monitor, clear stale lease fields and set its next due time without executing a probe.
- Viewers cannot pause monitors.
- Members cannot pause another tenant's monitor.
- Archived monitors cannot be resumed.


## Scheduler integration coverage (7 D1-backed tests)

- Claims only enabled monitors whose due time has arrived, in deterministic order, and respects the caller's bounded batch size.
- Two overlapping claim calls cannot claim the same monitor.
- Expired leases can be reclaimed; an old lease token cannot release a newer worker's claim.
- Result finalization appends one check and advances the next-check time only for the current lease owner.
- Failed checks increment the consecutive-failure count; successful checks reset it.
- Invalid batch limits, lease durations and check-result fields are rejected.
- Soft-deleted monitors cannot be claimed, and an in-flight result cannot be finalized after archive.

These tests use isolated local D1. They do not invoke a Cron Trigger, contact customer URLs or assert production scheduler throughput/lag.


## Incident lifecycle integration coverage (3 D1-backed tests)

- An incident is opened only after the configured consecutive-failure threshold; repeated failures keep one active incident and do not duplicate the open event.
- The first successful check moves the active incident to monitoring; the configured recovery threshold resolves it.
- A failure during recovery reopens the same incident rather than creating a second active incident.
- Database updates to incident timeline events are rejected by the migration trigger.

## Incident action integration coverage (7 D1-backed tests)

- Members can append internal and public timeline notes; the API returns actor attribution and visibility.
- Members can advance an incident through the supported investigation, identified, monitoring and resolved states.
- A resolved incident rejects later customer-authored updates.
- Viewers cannot add notes or change incident status.
- Cross-tenant incident mutations are denied without appending timeline or audit records.
- Invalid transitions, empty/oversized/control-character messages and unsupported visibility values are rejected.
- Concurrent status transitions append only one event; the stale request receives a conflict response.
- Timeline writes are rate-limited after 30 requests in a 15-minute window from the same source IP.

These tests exercise the actual Worker entrypoint against isolated D1. Public visibility is stored for future status-page publishing but does not publish an external page. Notification fan-out, retention/deletion semantics and live probe-driven incidents remain untested.


## Browser script syntax validation

CI runs `npm run check:inline-js`, which parses (but does not execute) inline JavaScript in each HTML file under `apps/web`. The current verified run parsed four scripts across four HTML files. This catches syntax errors in the static HTML application but is not a substitute for browser E2E, responsive-layout, keyboard-navigation or accessibility testing.


## Read-only API key integration coverage

The API integration suite now exercises API key creation and revocation through the Worker, verifies that only a hash is persisted and that list responses never expose the secret, confirms that `last_used_at` updates, and checks that revoked/expired keys are rejected. Bearer keys are restricted to their issuing workspace and read-only monitor/incident endpoints; tests reject cross-tenant reads and monitor mutations, deny authentication/team routes, and ensure internal incident timeline notes are not exposed. Owners/admins can manage keys; members/viewers cannot. An explicit bearer header takes precedence over an ambient session cookie, and an invalid bearer never falls back to a valid cookie. These tests use isolated D1 and do not contact an external provider.


## Status-page integration coverage

The status-page API tests run against the actual Worker entrypoint and isolated D1. They cover draft creation and audit logging, publication, public-only incident updates, omission of raw target URLs/monitor IDs/workspace identifiers, unknown health while probes are disabled, invalid and cross-tenant monitor associations, the database tenant trigger, viewer read/write boundaries, the requirement for at least one component, archive/unpublish behavior, prevention of removing the final component from a published page, automatic unpublishing when its final monitor is soft-deleted, and API-key denial.

The static `apps/web/status.html` renderer is included in the existing inline-script syntax check. This check parses JavaScript but does not execute browser flows; responsive, keyboard, screen-reader and public-page browser acceptance remain outstanding. No external Cloudflare resources or live monitor targets are contacted by these tests.


The status-page implementation passed GitHub Actions run [#182](https://github.com/learninghub44/zetuwatch/actions/runs/43568666409): TypeScript, inline browser JavaScript syntax (five HTML files), SQLite migration validation (seven migrations) and the full Vitest suite (13 files, 129 tests). This does not replace browser E2E or accessibility testing.


## Email notification integration coverage

The notification suite runs against the actual Worker entrypoint and isolated local D1. It covers verified-self-email channel creation, role and tenant restrictions, channel disable cancellation, scheduler-finalizer event enqueue, exactly-once event/channel rows, provider success and stable idempotency keys, rate-limit retries, concurrent scheduled invocations, expired lease rejection/reclaim, concurrent Resend idempotency 409 retry, and workspace-scoped delivery-log reads. Unit tests cover bounded retry delays, Retry-After delta-seconds/HTTP-date parsing, strict ISO timestamp input and lease-token whitespace rejection.

All provider calls are intercepted with an injected/mock fetch. These tests do not send real email, verify a Resend domain, validate a production API key, or prove mailbox delivery. The notification feature branch still requires full GitHub Actions verification and browser acceptance.


Additional notification regression cases verify that delivery history remains visible to the channel creator after channel removal (the channel foreign key becomes null), application links reject unsafe protocols and embedded credentials, subject CR/LF control characters are removed, and dispatch does not claim queued work when provider/sender/application configuration is absent.

The combined one-minute scheduled handler is covered by a D1 integration test that fires the Cron event without probe bindings and verifies no monitor lease or check is created. Email delivery is skipped when provider/sender configuration is absent.


## Webhook endpoint, dispatcher and history coverage

The webhook endpoint integration suite uses the actual Worker entrypoint and isolated D1. It covers owner/admin mutation permissions, member/viewer denial, API-key denial, cross-tenant isolation, HTTPS destination syntax rejection, duplicate and ten-endpoint limits, encrypted URL/secret persistence, tenant/endpoint/field-bound AAD, one-time secret responses, secret rotation, rename, removal scrubbing and audit records. New cases cover operator-gated activation and tenant-scoped delivery history/attempt metadata without exposing endpoint secrets.

The test encryption key is a deterministic, non-production Miniflare binding in `vitest.config.mts`. It must never be reused in a deployed environment. Endpoint creation, rename, rotation and activation make no DNS or HTTP request.

Webhook HMAC unit tests verify exact raw-body signing, tamper detection, wrong-secret rejection, malformed headers, stale/future timestamps, invalid tolerance and payload-size bounds.

The webhook outbox suite verifies tenant-safe event fan-out, public/internal visibility filtering, unique event/endpoint idempotency, lease claims/reclaims, attempt logging, retry scheduling, stale settlement rejection, terminal success, endpoint-disable cancellation and append-only attempt history.

The new `tests/webhook-dispatch.integration.test.ts` injects a fake sender while exercising the actual D1 dispatcher. It covers successful signed-body delivery, event ID and payload shape, exclusion of private notes, incident summaries and target URLs, inclusion of explicitly public update text, transient 503 retry scheduling, endpoint disable during an in-flight request, and the default-off operator gate. It does not open an external socket or resolve customer DNS. A delayed-Cron regression case also proves the 90-second lease starts when the webhook batch actually claims work, not at the earlier invocation timestamp used for the due-work cutoff.

The new `tests/webhook-endpoints.integration.test.ts` cases cover owner/admin activation policy, a 503 when operator configuration is absent, and delivery/attempt history tenant isolation. The history response is checked for absence of ciphertext, secrets and private incident text.

## Webhook egress agent coverage

Node tests cover strict webhook-job normalization, HTTPS/default-port destination policy, IP-literal and local/special-use hostname rejection, event-ID/body binding, timestamp freshness, canonical base64url and payload-size bounds, A/AAAA mixed-answer rejection, DNS pinning, original hostname/SNI and TLS verification, redirect non-following, bounded Retry-After, response classification, total-deadline enforcement, Worker-to-agent HMAC signing, route authentication/replay protection and separate webhook request-body limits.

The existing focused Node runner/transport/client suite previously passed 18 tests on Node v22.16.0. That does not verify the newly added Worker dispatcher. The new Worker/D1 tests and current full repository typecheck, inline browser script check, migration validation, Vitest suite and Node suite must run on the latest branch head before webhook delivery can be considered verified. No production TLS handshake or live receiver delivery has been performed.


## Webhook master-key rotation coverage

- Unit tests verify legacy `v1` AAD compatibility, current/previous key selection, invalid key ids, missing/duplicate key configuration and unavailable-key fail-closed behavior.
- D1 integration tests verify that both endpoint ciphertexts move to the current key while the destination, signing secret and suffix remain unchanged; bounded batches resume; concurrent rotation workers cannot overwrite one another; destination-hash/authentication failures leave rows untouched; and unknown key ids are reported as blocked rather than guessed.
- Dispatcher integration tests verify that legacy rows remain deliverable through the previous key during rotation and that re-encrypted rows deliver with the new current key after the previous key is removed.
- Migration validation checks the legacy `v1` default, accepted key-id syntax, rejected unsafe key ids and the key-rotation index.

These tests use the isolated local D1/Workers runtime and test-only keys. They do not configure Cloudflare secrets, deploy a Worker, or exercise production key management. The new migration, keyring, rotation worker and integration tests must pass the complete pinned repository CI on the latest branch head before the feature is considered verified.


## Durable probe-agent replay protection

- The Worker/D1 integration suite verifies exact raw-body HMAC validation, timestamp freshness, nonce/header-body binding, browser-origin rejection, request-size bounds, expired-row pruning and atomic duplicate rejection under concurrent claims.
- The Node agent suite verifies that production replay claims use the exact HTTPS Worker endpoint, sign the claim body with the shared secret, reject redirects, map D1 duplicate responses to replay rejection and fail closed when the Worker is unavailable. The standalone server requires `PROBE_REPLAY_URL`; the in-memory fallback is only for isolated handler tests.
- The database stores only a SHA-256 nonce hash and expiry timestamp. These tests use isolated local D1 and test-only bindings; they do not prove a deployed Worker/agent network path or production secret configuration.
