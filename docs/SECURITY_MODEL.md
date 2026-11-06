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
- rejects localhost and selected non-public IPv4 ranges;
- rejects IPv6 literals until a complete address classifier and pinning-capable egress layer exists;
- rejects local/test/internal suffixes and single-label hostnames;
- caps URL length.

The HTTP probe currently:
- permits GET and HEAD only;
- disables automatic redirects;
- sets a bounded timeout;
- measures time to response headers and cancels the response body;
- does not accept arbitrary customer headers or credentials.

This is not a production SSRF boundary. Cloudflare Workers supports both HTTP fetch and an outbound TCP socket API. The current implementation uses fetch, which does not expose a DNS answer that application code can validate and pin to the exact outbound socket. The TCP socket API may enable a custom HTTP/TLS prober, but the project has not yet demonstrated a complete DNS-resolution, address-pinning, TLS hostname-verification and redirect-validation flow on that runtime. Consequently, hostname checks in this repository cannot currently guarantee protection against DNS rebinding or a public hostname resolving to a private address.

Do not expose monitor creation or execute arbitrary customer targets in a production environment until one of these approaches is implemented and independently tested:

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

## Operational requirements before public launch

- Per-user, per-organization and global monitor creation/check quotas.
- Abuse reporting, automated suspension thresholds and audited admin overrides.
- No caller-controlled proxy headers, cookies, authorization headers or arbitrary ports.
- Redacted structured logs; no full response bodies or sensitive query strings.
- Scheduler concurrency and queue bounds; no unbounded fan-out from one cron event.
- Security review of the complete network path, not just URL parsing.

## Current status

The URL policy and HTTP probe have unit tests, but no production-grade DNS resolver/pinning egress layer exists yet. Treat outbound monitor execution as blocked for public production use until that gap is closed.
