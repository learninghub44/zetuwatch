# ZetuWatch security model and current egress boundary

## Security invariants

- Every customer-controlled URL is untrusted input.
- URL parsing is not DNS validation. A hostname can resolve to multiple IPv4/IPv6 addresses, and its answers can change between validation and connection.
- Redirects are new destinations. A redirect must never be followed unless the next hop independently passes the complete egress policy.
- A monitor response is untrusted. Do not persist arbitrary response bodies, headers, cookies, or credentials in check history.
- Tenant ownership must be enforced by server-side membership checks on every query and mutation. Hiding UI controls is not authorization.
- Secrets are displayed once, stored as hashes or encrypted values where required, and redacted from logs.

## Current implementation boundary

The URL and IP policy is shared as dependency-free ESM between the Worker and the standalone Node probe agent. The TypeScript entrypoints re-export that implementation so the two runtimes do not carry separate address-classification rules.

The URL gate:
- permits only HTTP and HTTPS;
- rejects embedded URL credentials;
- permits only the scheme's default port (80 for HTTP, 443 for HTTPS);
- rejects localhost, internal/test/example suffixes and single-label hostnames;
- rejects non-public IPv4 literals, including private, loopback, link-local, carrier-grade NAT, benchmarking, documentation, multicast and reserved ranges;
- rejects IPv6 URL literals; IPv6 DNS answers are classified and can be selected/pinned by the agent;
- caps URL length.

The dedicated agent in apps/probe-agent uses Node's built-in DNS and HTTP(S) modules. It resolves A and AAAA records, tolerates only ENODATA for an absent address family, caps the combined answer set at 16 and rejects the entire set if any address is non-public. DNS resolution is bounded to 2.5 seconds.

For each hop, the transport selects one validated address and supplies it through Node's custom lookup callback. The connection therefore uses that exact address instead of performing a second hostname lookup. HTTPS keeps the original hostname for SNI and leaves certificate verification enabled. Connection pooling is disabled. Redirects are manual; each next hop is parsed, revalidated, independently resolved and pinned. HTTPS downgrade, private destinations, disallowed ports, loops and excess hops are rejected.

The probe accepts GET and HEAD only and no caller-supplied headers or body. A total deadline of at most 30 seconds covers DNS and redirects. Response bodies are discarded and capped at 64 KiB; response headers are capped at 16 KiB. The signed Worker client requires the configured HTTPS agent endpoint, disables redirects, omits credentials and caps the normalized response at 4 KiB.

Worker-to-agent requests use HMAC-SHA-256 over a version, timestamp, nonce and body digest. The agent uses constant-time signature comparison, a 60-second clock window, five-minute in-memory nonce replay protection, a 16 KiB request-body limit, a 300-request-per-source-IP-per-minute limit and a 20-request concurrency bound.

This is a scheduler/egress implementation slice, not a launched monitoring service. The signed client is now integrated with a bounded D1 dispatcher on the secure-probe feature branch. Dispatch defaults to 10 claims per tick (hard maximum 15), counts unexpired leases across overlapping invocations to cap each workspace at two in-flight probes, and runs five concurrent agent requests; infrastructure failures defer work without recording a customer outage, and stale or expired lease tokens cannot finalize results. Finalization requires the original lease to remain unexpired at the check timestamp; recovery, resolution and reopening statements are additionally gated on the check row inserted by that same finalization batch, so an expired or superseded result cannot mutate incident state or enqueue lifecycle alerts. The Worker scheduled handler is gated by `PROBES_ENABLED=true` and validated agent configuration. `wrangler.toml` declares the shared one-minute Cron Trigger; email dispatch runs only when Resend sender/API configuration is present, while monitor probes remain skipped unless the operator explicitly supplies the probe bindings. The customer API continues to report `executionEnabled: false` until live execution is deliberately enabled. The agent has not been deployed or tested against a production DNS resolver or trusted public TLS certificate chain. The nonce cache is process-local, so the current service must run as a single instance; multi-instance operation requires a shared durable replay store.

Do not enable scheduled execution until the latest feature branch passes the full CI suite, the agent is deployed with operator-managed TLS and secret configuration, automatic incident transitions are connected to notification delivery, and a production-like Worker-to-agent-to-D1 test verifies DNS pinning, certificate failures, redirects, timeouts, response limits, retry deferral and persistence.

The agent must not become an unauthenticated general-purpose proxy. It accepts only signed, bounded monitor jobs and returns a small normalized result. It has no arbitrary headers, cookies, request body, custom ports, proxy support or caller-selected network route.

## Required egress test matrix

- IPv4 loopback, RFC1918, link-local, carrier-grade NAT, documentation, benchmarking, multicast and reserved ranges.
- IPv6 loopback, unique-local, link-local, IPv4-mapped IPv6, multicast and documentation ranges.
- IPv4-in-IPv6 and unusual numeric host representations.
- DNS A/AAAA answers containing a mixture of public and private addresses; absent-family ENODATA versus resolver failures.
- DNS rebinding between validation and connect, proving the custom lookup uses the selected address.
- Redirect chains to private, loopback, metadata, non-default-port and blocked-host destinations.
- Redirect loops, HTTPS downgrade and excessive hop counts.
- Slow DNS, slow headers, slow body, oversized headers/body, connection errors and abort behavior.
- TLS SNI uses the original hostname; trusted-certificate success, hostname mismatch and expired-certificate failures.
- Signed request tampering, stale timestamps, nonce replay, malformed jobs, body bounds, concurrency and rate limits.
- Worker client rejects insecure endpoints, redirects, oversized responses and malformed result shapes.

The Node probe-agent suite currently covers IP classification, mixed-answer rejection, injected DNS answers, pinned lookup behavior against a local HTTP server, redirect-hop validation, response-size bounds, TLS request-option defaults, HMAC compatibility, replay/stale request rejection and response validation. It does not yet perform live public DNS or a trusted-certificate TLS handshake. The Worker client is tested with an injected fetcher. The suite must pass in GitHub Actions before this implementation is treated as verified by CI.

## Operational requirements before public launch

- Per-user, per-organization and global monitor creation/check quotas.
- Abuse reporting, automated suspension thresholds and audited admin overrides.
- No caller-controlled proxy headers, cookies, authorization headers or arbitrary ports.
- Redacted structured logs; no full response bodies or sensitive query strings.
- Scheduler concurrency and queue bounds; no unbounded fan-out from one cron event.
- Security review of the complete network path, not just URL parsing.

## Current status

The URL/IP policy, Node DNS resolver, pinned HTTP(S) transport, manual redirect handling, signed Worker client and bounded agent HTTP server are implemented on the feature branch. Local Node tests and an isolated TypeScript declaration-resolution check passed during development. The CI workflow now runs the Node suite on feature branches, but a successful GitHub Actions run for this branch is still required.

The D1 scheduler integration and shared one-minute scheduled handler are implemented on the integration branch, but no customer-target probe has been enabled, the probe agent has not been deployed, and production-like Worker-to-agent-to-D1 verification has not been performed. The process-local replay cache limits the current agent to one instance. Keep monitor execution disabled and public status-page health unknown until the remaining integration and operational launch gates pass.

## Workspace API key boundary

- Keys use a cryptographically random 256-bit secret with the `zw_live_` prefix. Only a SHA-256 hash is stored; the full secret is returned once at creation and is never included in list responses or audit metadata.
- Only verified workspace owners/admins may create, list or revoke keys. Keys are bound to one organization, expire after 30, 90 or 365 days, and are capped at 10 active keys per workspace.
- A key remains valid only while its creator remains a verified owner/admin of that organization. Revocation is immediate and idempotent. Successful authentication updates `last_used_at`.
- The initial key scope is read-only: monitor list/detail/check history and incident list/detail. Keys cannot mutate monitors/incidents, access authentication/team-management routes, or read internal incident timeline notes.
- Keys are accepted only in an `Authorization: Bearer` header, never in query parameters. When the header is present it takes precedence over session cookies, and an invalid bearer never falls back to a cookie. Treat them as server-side secrets; do not embed them in browser bundles, URLs, logs or source control. The workspace UI displays the secret once and does not persist it in browser storage.


## Public status-page boundary

- A public page is served only when `is_published = 1` and `archived_at IS NULL`. Draft, unpublished and archived slugs return 404.
- The public response is an allowlist: page name/slug/description, component name/type/state, and timeline events explicitly marked `public`. It omits monitor IDs, target URLs, organization IDs, internal notes and actor account details.
- Health is always `unknown` while scheduled execution is disabled. A configured or enabled monitor is not evidence of a successful check. Public pages must not infer uptime from configuration or old fixture data.
- The API checks organization membership for every page read/write and reserves create/update/publish/archive for owners/admins. Read-only API keys are explicitly denied.
- D1 triggers reject cross-organization monitor associations, including direct SQL writes. Soft-deleting the final live component automatically unpublishes its page; archive also unpublishes without deleting the record.
- Public updates are authored by workspace users through the incident API and must have `visibility = 'public'`. The public page query filters at the database layer; it does not fetch internal events and hide them in the browser.
- The public renderer uses `textContent`/DOM nodes for all database-backed strings. It does not interpolate page content into HTML or execute scripts from stored values.

This is a public information surface, not a live service-health assertion. Do not remove the explicit unknown-state notice until the secure outbound runner and real measurements are enabled and independently verified.


- The standalone probe agent uses a per-hostname Node DNS resolver with a shared A/AAAA deadline and cancels outstanding DNS queries on timeout. This keeps timed-out resolver work within the same bounded probe lifetime instead of allowing abandoned DNS requests to accumulate after an active slot is released.

## Email notification boundary

- An email channel can target only the creating user's own verified account address. The channel is tied to a current verified workspace member; arbitrary recipient addresses are rejected.
- Owners/admins can manage all workspace channels. Members can manage only their own channel; viewers are read-only. Read-only API keys cannot access channel or delivery-log routes.
- Email templates HTML-escape organization, monitor, incident and timeline text. They contain no monitor target URL, response body, customer headers or stored credentials. Provider errors are reduced to fixed error codes; response bodies and API credentials are not logged.
- Incident event enqueue is idempotent per immutable event/channel through a unique database index. Delivery claims are bounded (maximum 10, default 5) and use expiring leases. Settlement and context loading require the lease to remain active, so an expired worker cannot overwrite a later claim.
- Resend receives a stable event/channel idempotency key on every retry. Its documented idempotency retention is 24 hours; the local retry schedule ends in under eight hours. The provider's concurrent-idempotency 409 response is retried; a payload/idempotency conflict is terminal.
- Transient network, timeout, rate-limit and provider 5xx failures use bounded retries. Retry-After is parsed as delta-seconds or an HTTP date and capped at six hours. Six total attempts are allowed.
- Disabling/removing a channel cancels queued deliveries. It cannot recall a request already accepted by the provider; this limitation is disclosed in the UI.
- The dispatcher skips sending when Resend credentials or sender configuration are missing. No real provider delivery has been verified. Never add provider secrets to source control, client code, logs or API responses.
- Delivery rows retain a non-secret channel-creator identifier independently of the nullable channel foreign key. Removing a channel preserves the creator's delivery history while they remain in the workspace.
- Email subjects strip control characters, plain text is normalized, and application links are constructed only from HTTPS origins (localhost HTTP only for development); URL credentials and unsafe protocols are rejected.
- Customer-authored `incident.update` and `incident.status_changed` events are emailed only when visibility is explicitly public. Internal notes/status transitions are excluded at enqueue and checked again before provider delivery.

