# ZetuWatch security model and current egress boundary

## Security invariants

- Every customer-controlled URL is untrusted input.
- URL parsing is not DNS validation. A hostname can resolve to multiple IPv4/IPv6 addresses, and its answers can change between validation and connection.
- Redirects are new destinations. A redirect must never be followed unless the next hop independently passes the complete egress policy.
- A monitor response is untrusted. Do not persist arbitrary response bodies, headers, cookies, or credentials in check history.
- Tenant ownership must be enforced by server-side membership checks on every query and mutation. Hiding UI controls is not authorization.
- Secrets are displayed once, stored as hashes or encrypted values where required, and redacted from logs.

## Current implementation boundary

The monitoring-core URL validator currently provides a syntactic first gate:
- permits only HTTP and HTTPS;
- rejects embedded URL credentials;
- restricts ports to 80 and 443;
- rejects localhost, internal/test suffixes and single-label hostnames;
- rejects non-public IPv4 literals, including private, loopback, link-local, carrier-grade NAT, benchmarking, documentation, multicast and reserved ranges;
- rejects all IPv6 URL literals until a pinned IPv6 transport is implemented;
- caps URL length.

A dependency-free address classifier parses canonical IPv4 and IPv6 records and permits only conservative global-unicast ranges. Its DNS answer-set helper rejects empty, malformed, oversized or mixed public/private A/AAAA sets rather than selecting only the first apparently safe record. IPv6 DNS answers are classified even though IPv6 monitor destinations remain disabled.

A DNS adapter now queries Cloudflare's documented DNS-over-HTTPS JSON endpoint for A and AAAA records in parallel. It bounds each response to 16 KiB and each query to at most five seconds, rejects redirects and non-success DNS responses, and validates the combined answer set. This adapter is not yet called by monitor execution and does not pin the resolved address to a socket.

The HTTP probe currently:
- permits GET and HEAD only;
- disables automatic redirects;
- sets a bounded timeout;
- measures time to response headers and cancels the response body;
- does not accept arbitrary customer headers or credentials.

This is not a production SSRF boundary. Cloudflare Workers ordinary fetch() does not expose a DNS answer that application code can validate and pin to the exact outbound socket. The new resolver is a separate policy component; it is not yet connected to the probe transport. The project has not demonstrated a complete DNS-resolution, address-pinning, TLS hostname-verification and redirect-validation flow on the target runtime.

Do not expose monitor execution in production until one of these approaches is implemented and independently tested:

1. A dedicated egress/probe service that resolves all A/AAAA records, rejects the destination if any answer is non-public, pins the validated address to the actual connection while preserving TLS SNI/Host verification, validates every redirect hop, and enforces connection/read/total timeouts and response-size limits; or
2. A Cloudflare-supported outbound networking primitive that provides equivalent address validation and connection pinning, verified against current platform documentation and tests.

The egress service must not become an unauthenticated general-purpose proxy. It should accept only authenticated, signed, bounded monitor jobs from the scheduler, enforce per-tenant and global quotas, and return a small normalized result.

## Required egress test matrix

- IPv4 loopback, RFC1918, link-local, carrier-grade NAT, documentation, benchmarking, multicast and reserved ranges.
- IPv6 loopback, unique-local, link-local, IPv4-mapped IPv6, multicast and documentation ranges.
- IPv4-in-IPv6 and unusual numeric host representations.
- DNS answers containing a mixture of public and private addresses.
- DNS rebinding between validation and connect.
- Redirect chains to private, loopback, metadata and non-standard-port destinations.
- Redirect loops and excessive hop counts.
- Slow headers, slow body, oversized body, connection errors and abort behavior.
- Attempts to access cloud metadata endpoints and internal service names.

The pure IP classifier, mixed-answer-set policy and DNS-over-HTTPS adapter have unit coverage. The adapter's timeout, response-size and fail-closed behavior are tested with injected responses; live resolver behavior and DNS rebinding between validation and connection remain unverified. Redirect transport, HTTP response limits and abuse controls remain unimplemented.

## Operational requirements before public launch

- Per-user, per-organization and global monitor creation/check quotas.
- Abuse reporting, automated suspension thresholds and audited admin overrides.
- No caller-controlled proxy headers, cookies, authorization headers or arbitrary ports.
- Redacted structured logs; no full response bodies or sensitive query strings.
- Scheduler concurrency and queue bounds; no unbounded fan-out from one cron event.
- Security review of the complete network path, not just URL parsing.

## Current status

The URL policy, fail-closed HTTP probe, pure IP classifier and bounded DNS resolver component have unit tests. No DNS-pinned transport or complete production-grade egress layer exists yet. Treat outbound monitor execution as blocked for public production use until that gap is closed.


## Workspace API key boundary

- Keys use a cryptographically random 256-bit secret with the `zw_live_` prefix. Only a SHA-256 hash is stored; the full secret is returned once at creation and is never included in list responses or audit metadata.
- Only verified workspace owners/admins may create, list or revoke keys. Keys are bound to one organization, expire after 30, 90 or 365 days, and are capped at 10 active keys per workspace.
- A key remains valid only while its creator remains a verified owner/admin of that organization. Revocation is immediate and idempotent. Successful authentication updates `last_used_at`.
- The initial key scope is read-only: monitor list/detail/check history and incident list/detail. Keys cannot mutate monitors/incidents, access authentication/team-management routes, or read internal incident timeline notes.
- Keys are accepted only in an `Authorization: Bearer` header, never in query parameters. When the header is present it takes precedence over session cookies, and an invalid bearer never falls back to a cookie. Treat them as server-side secrets; do not embed them in browser bundles, URLs, logs or source control. The workspace UI displays the secret once and does not persist it in browser storage.
