# Dedicated probe agent

ZetuWatch uses Cloudflare Workers and D1 for the customer API and control plane. A Worker does not expose the DNS answer used by its ordinary outbound fetch in a way that lets application code pin the validated address to the exact socket. The customer-target network request therefore belongs in a separately operated egress process, not in an ordinary Worker fetch.

## Components

- The shared URL and IP policy lives in packages/monitoring-core as dependency-free ESM. The existing TypeScript entrypoints re-export that exact implementation so the Worker and agent do not maintain separate address-classification rules.
- The agent lives in apps/probe-agent and uses only Node.js built-in modules. It does not use an HTTP proxy, browser cookies, customer-supplied request headers or a third-party networking package.
- The Worker-compatible signed client lives in packages/probe-client. It uses Web Crypto and fetch to call only the configured HTTPS agent endpoint.
- The agent is not yet called by the scheduler. No customer target is probed by this change, and executionEnabled remains false.

## Request and trust boundary

1. The control plane sends a bounded job containing targetUrl, GET or HEAD, expected status, timeout and redirect limit. Additional fields are rejected.
2. The Worker client requires an HTTPS endpoint at the exact /v1/probe path, omits credentials, disables redirects and signs the exact JSON body.
3. The signature is HMAC-SHA-256 over the version, Unix timestamp, nonce and SHA-256 body digest. The agent compares signatures in constant time, accepts only a 60-second clock window and rejects a nonce reused during its five-minute replay window.
4. The agent validates the URL again. It rejects credentials, unsupported protocols, non-default ports, blocked/local suffixes, malformed numeric hosts and non-public IP literals. Only GET and HEAD are accepted.
5. For a hostname, the agent resolves A and AAAA records. Only an empty answer for one address family is tolerated; other resolver errors fail closed. The combined set is capped at 16 and rejected if any address is non-public.
6. The agent chooses a validated address and passes it to Node HTTP(S) through a custom lookup callback. The callback returns that address instead of performing a second DNS lookup. HTTPS retains the original hostname as SNI and leaves certificate verification enabled. Connection pooling is disabled so a later job cannot reuse a socket established under a different validation decision.
7. Redirects are manual. Each next URL is parsed and revalidated, then independently resolved and pinned. HTTPS-to-HTTP downgrade, private destinations, non-default ports, loops and excess hops are rejected.
8. The response body is discarded. The agent returns only a normalized status, elapsed time, error category and redirect count.

## Bounds

- DNS A/AAAA resolution: 2.5 seconds.
- Total probe deadline: at most 10 seconds, including DNS and redirect hops.
- Redirects: disabled by default; maximum 3 when explicitly requested.
- Response body: 64 KiB maximum.
- Response headers: 16 KiB maximum.
- Agent request body: 16 KiB maximum.
- Agent request rate: 300 requests per source IP per minute.
- Concurrent in-flight agent requests/probes: 20 maximum.
- Worker-to-agent response: 4 KiB maximum.
- Only ports 80 for HTTP and 443 for HTTPS are accepted.

## Running the agent

Requires Node.js 22.12 or later. There are no additional runtime npm dependencies.

Configure these environment variables outside source control:

- PROBE_TLS_CERT_FILE: path to the agent HTTPS certificate chain.
- PROBE_TLS_KEY_FILE: path to the matching private key.
- PROBE_SHARED_SECRET: a random secret of at least 32 bytes, shared with the Worker secret store.
- PROBE_PORT: optional listener port; defaults to 8788.
- PROBE_HOST: optional bind address; defaults to 0.0.0.0.

Generate a secret locally with a cryptographically secure generator such as openssl rand -hex 32, then place it in the host's secret manager and the Worker secret store. Never put the value in wrangler.toml, a checked-in .env file, CI logs or this repository.

Start the service with node apps/probe-agent/src/server.mjs. It requires TLS files and the shared secret at startup. GET /healthz returns only a minimal status value. POST /v1/probe requires the signed request headers.

The nonce replay cache is currently in process memory. Run one agent instance only. Do not add replicas or load balancing until a shared durable nonce store is implemented and tested; otherwise a captured signed request could be replayed against another replica. The source-IP rate limit is an additional abuse control, not a tenant quota. Tenant and plan quotas must be enforced by the Worker scheduler before dispatch.

## Tests and verified limits

Run npm run test:probe-agent. The suite covers IP classification, mixed DNS answer rejection, address pinning, redirect re-resolution, private/downgrade/loop rejection, response bounds, TLS SNI and certificate-verification options, HMAC compatibility, stale timestamps, replay rejection, malformed jobs and response validation.

These tests use injected DNS answers and a local HTTP server. They do not perform live public DNS resolution or a trusted-certificate TLS handshake. The TLS test verifies the Node request options (original SNI hostname and rejectUnauthorized enabled), not a production certificate chain. The Worker client is tested with an injected fetcher; it has not been connected to the production scheduler or a deployed agent.

## Launch blockers

- Integrate the signed client with the bounded scheduler and persist actual check results only after a valid agent response.
- Add per-organization dispatch quotas and a durable, shared replay store before multi-instance operation.
- Exercise a real HTTPS handshake using a trusted test certificate and verify hostname mismatch/expiry failures.
- Verify DNS behavior and outbound network restrictions in the intended host environment.
- Deploy the agent and configure its URL/TLS/secret only after explicit deployment authorization.
- Complete a production-like Worker-to-agent-to-D1 end-to-end test before enabling Cron.

Until those gates pass, scheduled monitoring stays disabled and public status pages must continue to report health as unknown.


## DNS query cancellation

The agent creates an isolated Node `dns/promises.Resolver` for each hostname, limits the resolver to one attempt per query, and uses one shared deadline for the A/AAAA pair. If that deadline expires, it calls `resolver.cancel()` before returning `DNS_TIMEOUT`; a timed-out target therefore cannot leave DNS queries running after the probe slot has been released. This uses the documented Node resolver timeout, retry and cancellation APIs: https://nodejs.org/api/dns.html#class-dnspromisesresolver.


The total deadline is recomputed after every DNS resolution. If DNS consumes the remaining budget, no HTTP socket is opened; otherwise the transport receives only the remaining time, not the stale pre-DNS budget.
