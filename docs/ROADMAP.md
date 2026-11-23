# Product roadmap

The product is built in vertical slices. A slice is complete only when UI, API, persistence, authorization, tests, documentation and operational visibility are present.

## Phase 0 — foundation
- [x] Public repository and project documentation
- [x] Initial D1 schema
- [x] Worker API health endpoint
- [x] Conservative HTTP probe foundation
- [x] Product scope and user journey specification
- [x] CI typecheck workflow added and verified in GitHub Actions
- [ ] Unit and integration test suite (115 tests across 13 files passed CI in run #175 on commit `a6cac79dcd3ccc2865629d93829d6e5cb0a782e8`; payment lifecycle coverage, browser E2E and provider tests remain)
- [x] Direct development-tool versions checked against current package releases and pinned
- [ ] Lockfile generation and clean-install verification

## Phase 1 — secure account foundation
- [ ] Authentication foundation: registration, email verification, password login/reset and opaque sessions are implemented; a D1-backed test now covers registration → verification → login → password reset → session revocation with email delivery stubbed; browser E2E, live provider delivery and security edge-case tests remain
- [ ] Invitation acceptance and full team/member management (member listing, role policy, invitations, acceptance, role changes, removal API and initial responsive team screen implemented; team member-list isolation, single-use concurrent invitation acceptance and concurrent owner demotion are covered by D1 integration tests; browser acceptance and real email delivery remain)
- [ ] Organization creation and basic membership checks exist; team-management API now enforces owner/admin/member/viewer policy and last-owner protection; monitor/team tenant boundaries, invitation consumption and concurrent owner protection pass D1-backed API tests, while broader route coverage remains
- [ ] Tenant-safe schema constraints and migration tests (six numbered migrations passed CI SQLite validation and the API/scheduler/incident suites load them in isolated local D1 in run #175; production-account D1 behavior remains unverified)
- [ ] Audit events and basic per-IP auth/monitor rate limits exist; broader abuse controls remain

## Phase 2 — first working monitoring loop
- [ ] Basic tenant-scoped monitor create/list/read/update/delete API and responsive setup screen implemented; 18 D1-backed API tests now cover monitor/team boundaries, member/viewer permissions, invitation/owner concurrency, tenant-scoped incident reads, soft deletion, persisted check-history reads and idempotent pause/resume controls, while the full route matrix and browser acceptance remain
- [ ] Safe URL/egress policy: shared IPv4/IPv6 classification, Node A/AAAA resolution, mixed-answer rejection, custom lookup address pinning, TLS SNI/verification defaults, per-hop redirect validation, downgrade/loop rejection, GET/HEAD-only requests, scheme-default ports, 2.5s DNS bound, 30s total probe bound, 64 KiB response cap, 16 KiB header/body caps and an HMAC-signed Worker client are implemented on feat/secure-probe-agent; the latest branch's complete Node suite and repository CI, trusted-certificate TLS handshake, live DNS behavior and production egress verification remain unverified
- [ ] Probe-agent deployment and Worker integration: the gated D1 scheduler uses the signed client, per-workspace claim quotas, bounded concurrency, infrastructure retry deferral and lease-token finalization; a one-minute Cron Trigger is declared for the shared handler, but probe secrets are absent, the agent remains single-instance with in-memory replay protection, and trusted TLS/DNS plus production-like Worker-to-agent-to-D1 verification remain launch blockers
- [x] Atomic due-work claim leases and D1-backed check finalization primitive (bounded batches, lease expiry/reclaim, token ownership and check-history persistence are integration-tested; no Cron execution or real probes are enabled)
- [ ] Bounded scheduled runner / Cron Trigger integration (the shared one-minute handler and bounded D1 dispatch are implemented; probes remain gated off without explicit bindings, while full CI, live load/lag/retry and end-to-end behavior remain unverified)
- [ ] HTTP/HTTPS checks, history and latency
- [ ] Incident confirmation, deduplication and recovery (D1-backed finalization confirms, deduplicates, monitors, resolves and reopens incidents; tenant-scoped incident list/detail APIs now return the timeline to workspace members. Member/admin/owner incident status transitions, internal/public customer-authored timeline notes, actor attribution, audit writes and responsive controls are implemented; seven D1-backed Worker API integration tests were added. Public updates are stored but not published; email lifecycle events now enter the durable outbox, while full CI, browser E2E/accessibility and live provider delivery remain. Monitor deletion now soft-deletes and retains check, incident and timeline rows; retention and hard-purge workflows remain.)
- [ ] Verified email alerts and delivery history (verified-self-email channels, durable outbox, bounded retries, delivery-log API and responsive Alerts UI are implemented in this integration branch; full CI, browser acceptance and live Resend delivery remain)

## Phase 3 — complete customer experience
- [ ] Public marketing website, docs and pricing
- [ ] Multi-step sign-up and resumable onboarding
- [ ] Workspace overview, monitor list/create/delete, monitor detail, persisted check-history views and role-aware pause/resume controls are implemented; browser E2E, real measurements and analytics remain
- [ ] Incident timeline and customer-facing updates (tenant-scoped list/detail, role-protected status transitions, authored internal/public notes and responsive controls are implemented; public publishing, browser QA/accessibility and notification delivery remain)
- [ ] Status-page builder and public status pages
- [ ] Team invitations, roles and organization settings (initial member/invitation screen and API implemented; tenant-isolated member listing, concurrent invitation acceptance and owner-demotion protection are integration-tested, while complete settings, email delivery and browser QA remain)
- [ ] Analytics, exports and maintenance windows

## Phase 4 — revenue and integrations
- [ ] Plan/usage enforcement and transparent upgrade UX
- [ ] Payment provider integration after merchant activation and callback verification
- [ ] Receipts, renewals, failed-payment and cancellation workflows
- [ ] Webhook alert channel with signing and retries
- [ ] SMS credits/add-ons only after cost and provider validation

## Phase 5 — advanced monitoring and scale
- [ ] API response assertions and secret-safe custom headers
- [ ] SSL/domain expiry checks
- [ ] Cron heartbeat monitors
- [ ] TCP and DNS monitors after egress controls
- [ ] Multi-region probes with verifiable independent locations
- [ ] Retention tiers, audit exports and advanced access controls

## Production launch gates
- [ ] SSRF review and abuse controls signed off
- [ ] Authentication and tenant isolation tests pass
- [ ] Scheduler load/lag and retry behavior tested
- [ ] Notification delivery and unsubscribe tested
- [ ] Backup and restore procedure exercised
- [ ] Privacy, terms, retention and deletion workflows published
- [ ] Billing webhooks tested against duplicate, delayed and invalid events
- [ ] Accessibility and mobile QA completed
- [ ] Cloudflare quotas, limits and costs validated against target load, including the 10 ms Workers Free Cron CPU limit versus 30 seconds on Workers Paid for sub-hour schedules; the 10-job probe batch has not yet been measured against either plan
- [ ] Production deployment and smoke tests completed

Do not mark a phase complete because files or mock screens exist. Verify behavior.


## Incident action implementation update (2026-11-11)

- Added migration `0005_incident_updates.sql` with optional timeline actor attribution, internal/public visibility and a visibility/time index.
- Added owner/admin/member-only incident status transitions with a guarded state machine, conflict handling for concurrent transitions, resolved timestamps, timeline event inserts and audit events. Existing database protection blocks event updates, but monitor deletion still cascades event history.
- Added owner/admin/member-only customer-authored timeline notes with a 500-character limit, control-character rejection and explicit internal/public visibility.
- Incident detail reads now include event visibility and actor display names when the account still exists.
- Added six D1-backed integration tests for authorship, visibility, status lifecycle, viewer denial, cross-tenant denial, validation and concurrent transitions.
- Added responsive incident detail controls. Public visibility is only a stored classification for a future status-page publisher; no public page is published by this change.
- The API additionally rate-limits status and timeline writes to 30 requests per 15 minutes per source IP. The previous 100-test CI baseline is verified; CI verification of this new migration, API code, browser script and six additional tests is pending. The incident phase and production launch gates remain incomplete.

## Verified progress snapshot (2026-11-06)

- Added first-party email/password authentication endpoints and responsive account screens.
- Added email verification, resend-verification and password-reset token flows.
- Added workspace creation on registration and session-protected workspace lookup.
- Added tenant-scoped monitor configuration endpoints and a responsive monitor setup screen.
- Added migration smoke-test script and wired it into CI.
- Added a three-step monitor setup wizard, monitor editing and a contextual first-run checklist.
- Added unit tests for URL policy and fail-closed probe behavior.
- Added API/auth setup documentation.

**Verification recorded on 2026-11-06:** isolated TypeScript compilation and runtime checks for URL policy, HTTP probe and password hashing; SQLite migration smoke-test against the two current migration schemas. The complete repository CI had not yet been verified at that point.

**Deliberately disabled:** scheduled network probes. Current URL validation does not resolve and pin DNS addresses and is not sufficient protection against SSRF or DNS rebinding. No monitor should be represented as actively checked until the secure egress and scheduler phases are complete.

## Verification update (2026-11-07)

- Fixed a TypeScript 5.9 Web Crypto type error by copying decoded PBKDF2 salts into an owned `ArrayBuffer` before deriving bits. The password format and 310,000-iteration work factor are unchanged.
- Replaced an obsolete HTTP probe test that expected direct outbound fetches with an assertion that the probe remains blocked until SSRF-safe egress exists.
- GitHub Actions [CI run #71](https://github.com/learninghub44/zetuwatch/actions/runs/42346873713) completed successfully on commit `c7203ed2840f47cc608989dcd35fea39442f511e`.
- Verified in that run: full TypeScript typecheck; SQLite migration smoke-test (2 migrations, 16 required tables); Vitest (6 files, 53 tests).

**Still unverified:** API-level authentication and tenant-isolation integration tests, browser end-to-end flows, real Resend delivery, Cloudflare D1 behavior in the target account, production cookie/CORS behavior, scheduler and incident lifecycles, and payment/notification integrations.

**Security boundary unchanged:** no scheduled probes were enabled. Cloudflare Workers TCP sockets expose outbound connections but the documented API does not provide a demonstrated DNS-answer-to-socket pinning and TLS hostname-verification flow for this project. A dedicated, reviewed egress design is still required before running customer-controlled targets.


## Team management implementation update (2026-11-07)

- Added explicit role policy helpers for assigning roles, inviting users and removing members. Admins cannot grant admin/owner; only owners can grant admin; members can leave but cannot remove others.
- Added organization-scoped API endpoints to list members, create/list invitations, accept invitations, change roles and remove members. Membership is checked on every organization route; invitation acceptance requires a verified session whose email matches the invitation.
- Invitation tokens are random, stored as SHA-256 hashes, expire after seven days and are delivered through the configured Resend integration. Failed email delivery removes the pending invitation. Sensitive team actions emit audit events.
- Added role-policy unit coverage. The D1-backed API suite verifies cross-tenant team access, single-use concurrent invitation acceptance and concurrent owner demotion. UI browser acceptance and real Resend delivery verification are still required. The phase remains incomplete.


- Follow-up verification on 2026-11-07: added a workspace team screen with member listing, role controls, invitation form and pending-invitation view. The screen uses the authenticated workspace role to limit controls; the API remains authoritative. Last-owner continuity is a separately tested authorization policy.


## Verification update (2026-11-08)

- Added Cloudflare Workers Vitest integration with the MIT-licensed `@cloudflare/vitest-plugin` pinned to `1.6.0`. The test runtime uses the same compatibility date declared in Wrangler and isolated local D1 storage; it does not create or access a Cloudflare account resource.
- Added nine API integration tests against the actual Worker entrypoint and migrated D1 schema. In addition to session rejection, cross-tenant monitor listing/detail/history/create denial, member/viewer permission boundaries and cross-tenant team-member listing denial, the suite verifies single-use invitation acceptance under concurrent requests and protects the final owner when two owners concurrently attempt demotion.
- Added a D1-backed authentication lifecycle test covering registration, verification-token consumption, unverified-login rejection, session creation, workspace lookup, password-reset-token consumption and revocation of existing sessions. The Resend `fetch` call is stubbed inside the Worker test runtime; no real email is sent.
- GitHub Actions [CI run #99](https://github.com/learninghub44/zetuwatch/actions/runs/42456934904) completed successfully on commit `96454cd193a5b6f8f3c6ef7a0c4997cb4ab3bf0c`.
- Verified in that run: full TypeScript typecheck; SQLite migration smoke-test (2 migrations, 16 required tables); Vitest (8 files, 71 tests), including 9 tenant/team API integration tests and 1 authentication lifecycle integration test.

**Coverage boundary:** these tests verify core API session, tenant and role boundaries, not the complete authentication security/edge-case matrix, browser UX, live Resend delivery, production D1 account behavior, scheduler/incident lifecycles or provider callbacks. The corresponding launch gates remain open.

**Security boundary unchanged:** scheduled probes remain disabled. Cloudflare documents Workers DNS-over-HTTPS resolution and Node TCP/TLS APIs, but the exact pinned-IP HTTP/HTTPS path is not yet implemented or verified in the actual Worker runtime. Customer-controlled URLs must not be executed until the complete transport passes the SSRF, redirect, rebinding, timeout, response-size and abuse-control tests.


## Secure egress feasibility update (2026-11-08)

The current Cloudflare Workers runtime exposes useful primitives for a DNS-pinned design:

- [Node.js DNS compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/dns/) documents `dns.promises.resolve4()` and `resolve6()` through Cloudflare DNS-over-HTTPS at 1.1.1.1. It explicitly says `lookup()`, `lookupService()` and `resolve()` are not implemented; DNS calls count as subrequests.
- [Node.js net compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/net/) documents direct TCP connections through Workers sockets.
- [Node.js TLS compatibility](https://developers.cloudflare.com/workers/runtime-apis/nodejs/tls/) documents TLS client connections and certificate authorization APIs.
- [Workers TCP sockets](https://developers.cloudflare.com/workers/runtime-apis/tcp-sockets/) documents outbound socket restrictions and recommends ordinary `fetch()` for HTTP on ports 80/443. The exact interaction between direct-IP sockets, HTTP on those ports and TLS SNI/certificate verification therefore needs a real Worker prototype; the component APIs alone are not sufficient proof.

**Candidate implementation to verify:** resolve all A records; reject the hostname if any selected address is non-public; connect using a validated literal IP rather than resolving the hostname again; for HTTPS, preserve the original DNS hostname for SNI and certificate verification; send the original host in the HTTP Host header; disable automatic redirects and resolve/validate every redirect target before connecting. Keep IPv6 unsupported until its address classification and pinned transport are implemented. Bound DNS, connect, TLS and header time; cap redirects and response bytes; keep scheduled execution disabled until the complete path is verified.

No Cloudflare resources were created and no deployment was attempted. This is feasibility research, not an implemented or production-verified egress path.


## Address-classification implementation update (2026-11-09)

- Added a dependency-free IPv4/IPv6 parser and conservative global-address classifier for the egress layer.
- IPv4 special-use ranges include private, loopback, link-local, carrier-grade NAT, protocol assignments, documentation, benchmarking, multicast and reserved space. IPv6 is allowed by the classifier only within global-unicast space and excludes special-purpose, documentation and 6to4 transition ranges.
- Added a DNS answer-set guard that rejects empty, malformed, oversized or mixed public/non-public A/AAAA results; it never selects only the first apparently safe answer.
- Updated URL validation to use the shared IPv4 classifier and added regression coverage for unusual numeric IPv4 URL spellings. IPv6 URL literals remain rejected until a pinned IPv6 transport exists.
- This is a tested policy component only. It is not wired to a resolver or socket, does not prevent rebinding by itself and does not enable probes. The scheduled runner remains disabled.


## Address-classification CI verification (2026-11-09)

- GitHub Actions [CI run #103](https://github.com/learninghub44/zetuwatch/actions/runs/42572146791) completed successfully on commit `f467a24e9c2ee597abf1e0573d36bc6c1c43c382`.
- Verified: TypeScript typecheck; SQLite migration validation (2 migrations, 16 required tables); Vitest (9 files, 79 tests), including the new IPv4/IPv6 classification and mixed DNS-answer policy tests.
- The passing tests validate the pure policy code only. No runtime DNS resolver, pinned transport, redirect validation, scheduler or outbound probe was enabled.


## DNS resolver implementation update (2026-11-09)

- Added a Cloudflare DNS-over-HTTPS adapter using the documented JSON endpoint. It queries A and AAAA records in parallel and validates the combined set, rejecting any non-public answer.
- Added strict hostname validation, redirect rejection, a 16 KiB response-body cap, bounded per-query timeout and fail-closed handling for malformed, truncated and unsuccessful DNS responses.
- Added injected-fetcher tests; tests do not make live DNS requests or depend on external services.
- The resolver is a standalone component only. It is not yet wired to monitor execution, and it cannot prevent DNS rebinding until the transport connects to the exact validated IP without performing a second hostname lookup.


## DNS resolver CI verification (2026-11-09)

- GitHub Actions [CI run #106](https://github.com/learninghub44/zetuwatch/actions/runs/42573137900) completed successfully on commit `a70090c081bdd2d2b2229a62fd9ab8c92181c139`.
- Verified: TypeScript typecheck; SQLite migration validation (2 migrations, 16 required tables); Vitest (10 files, 89 tests), including the bounded DoH resolver, malformed-response handling, timeout and response-size tests.
- All DNS tests use injected responses; CI does not make live DNS requests. The resolver remains disconnected from monitor execution until a DNS-pinned transport is available.


## Scheduler claim/finalization implementation and CI verification (2026-11-10)

- Added migration `0003_scheduler_leases.sql` with monitor lease token, expiry and last-claimed timestamps plus a claim-selection index.
- Added `packages/scheduler-core/src/claims.ts`: D1 batch-based atomic claiming of due enabled monitors, a default batch of 10 with a hard maximum of 25, bounded 30–300 second leases, expired-lease reclamation, token-checked release and token-checked result finalization.
- Finalization appends one monitor check, advances the next-check time and updates the consecutive-failure counter in the same D1 batch. Stale workers cannot append a result after another invocation has reclaimed the lease.
- Added six isolated-D1 integration tests for due/disabled/future selection, batch bounds, overlapping claims, lease expiry/reclaim, stale token rejection, failure persistence and recovery of the failure streak.
- GitHub Actions [CI run #112](https://github.com/learninghub44/zetuwatch/actions/runs/42767560283) completed successfully on commit `8a682c85b4fdeafb8e55efc5d5de531b4de76a44`.
- Verified: TypeScript typecheck; SQLite migration validation (3 migrations, 16 required tables); Vitest (11 files, 95 tests), including six D1-backed scheduler integration tests.
- This durable claim/finalization layer is now connected to the DNS-pinned probe agent and shared scheduled handler. The one-minute Cron Trigger is declared, but customer probes remain disabled unless the operator explicitly configures `PROBES_ENABLED`, the HTTPS agent endpoint and shared secret. Live Worker-to-agent-to-D1 execution and full CI remain unverified.


## Incident lifecycle implementation and CI verification (2026-11-10)

- Added migration `0004_incident_lifecycle.sql` with a consecutive-success counter, a partial unique index enforcing at most one unresolved incident per monitor, and a database trigger that rejects updates to incident timeline events.
- Extended scheduler result finalization so monitor counters, check history and incident transitions are written in one D1 batch under the current lease token.
- Default policy: open after two consecutive failures; move an active incident to monitoring after the first successful check; resolve after two consecutive successful checks. Thresholds are configurable within bounded limits.
- A failed check during recovery reopens the same active incident instead of creating a duplicate. Repeated failures do not append duplicate incident-open events.
- Added three D1-backed lifecycle tests covering confirmation/deduplication, recovery and resolution, interrupted recovery/reopening, and rejection of timeline event updates.
- GitHub Actions [CI run #118](https://github.com/learninghub44/zetuwatch/actions/runs/42767973022) completed successfully on commit `163876decfe6a2c5d4fa3dde9a6a462e222ce51b`.
- Verified: TypeScript typecheck; SQLite migration validation (4 migrations, 16 required tables); Vitest (12 files, 98 tests), including six scheduler and three incident lifecycle integration tests.
- The state machine is a tested persistence primitive only. Read-only tenant-scoped incident list/detail APIs now exist, but there is no active Cron Trigger, real probe execution, incident UI, customer-facing status update or notification delivery. Timeline updates are blocked at the database layer, but monitor deletion still cascades timeline rows; a soft-delete/retention workflow is required before claiming full timeline immutability.


## Tenant-scoped incident read API and CI verification (2026-11-10)

- Added `GET /v1/incidents?organizationId=<id>` to list up to 100 incidents for a workspace after verifying the signed-in user's membership.
- Added `GET /v1/incidents/<uuid>` to return the incident and its ordered timeline only after verifying membership in the incident's owning workspace. Viewer roles retain read access; no mutation endpoint is exposed.
- Added two D1-backed API tests proving workspace incident lists do not include another tenant's incidents and that incident detail/timeline reads reject foreign-tenant access.
- GitHub Actions [CI run #124](https://github.com/learninghub44/zetuwatch/actions/runs/42768598741) completed successfully on commit `f9f208e1bbdc51f168da92d5c7b06145a8a934b3`.
- Verified: TypeScript typecheck; SQLite migration validation (4 migrations, 16 required tables); Vitest (12 files, 100 tests), including 11 API integration tests.
- Incident API coverage is read-only. Incident UI, customer-authored updates, notification fan-out, soft deletion and retention-aware timeline preservation remain incomplete.


## Incident dashboard read-only view and browser-script CI (2026-11-10)

- Enabled the Incidents navigation item on desktop and added a mobile shortcut to the incident section.
- Added a workspace incident list with monitor/target, start time, current state and resolution time. The open-incident statistic is derived from the API response.
- Added a read-only incident detail view with ordered timeline events. All dynamic content is inserted with DOM text nodes; the page does not render server-provided event text as HTML.
- Empty states explicitly say that live checks are not enabled; no incidents or uptime values are fabricated.
- Added `scripts/check-inline-js.mjs` and a CI step that syntax-parses inline scripts in all four web HTML files without executing browser code.
- GitHub Actions [CI run #133](https://github.com/learninghub44/zetuwatch/actions/runs/42769033337) completed successfully on commit `18b205a614b8680db26068b71e651cf5cb2477c8`.
- Verified: TypeScript typecheck; inline browser-script syntax check (4 scripts across 4 HTML files); SQLite migration validation (4 migrations, 16 required tables); Vitest (12 files, 100 tests).
- The incident page is read-only and depends on the tenant-scoped API. Browser interaction/accessibility tests, customer-authored updates and notification delivery remain open. No scheduled probes or live incident data are active.


## Monitor detail and persisted check history update (2026-11-11)

- Added a tenant-authorized monitor detail panel to the workspace app. The monitor list now has a View action, with monitor configuration, expected status, interval and an explicit scheduled-execution-disabled state.
- The detail panel reads the existing `GET /v1/monitors/<uuid>` and `GET /v1/monitors/<uuid>/checks` endpoints. It renders stored check timestamps, pass/fail values, HTTP status, response time and error category using text nodes only.
- Empty history is explicit. Refreshing the panel only reads persisted history; it never triggers a customer-target request or invents uptime/latency.
- Added a D1-backed API integration test proving a workspace viewer can read ordered persisted check history while the API continues to report `executionEnabled: false`.
- Added API and testing documentation. This monitor-detail/history slice was included in the 110-test suite that passed CI run #174 on commit `c3f19ade101af3abf1c16b47e598f1a7f1708d96`.
- The monitoring loop remains incomplete: no hardened outbound transport, Cron execution, new real checks, browser E2E, notification fan-out or production deployment is enabled.


## Monitor pause/resume implementation update (2026-11-12)

- Added tenant-authorized `POST /v1/monitors/<uuid>/pause` and `POST /v1/monitors/<uuid>/resume` actions. Owners, admins and members can manage monitor state; viewers remain read-only.
- Actions are idempotent and rate-limited. Pausing disables future claims and clears the current lease so a stale worker cannot finalize a result. Resuming clears stale lease fields and sets `next_check_at` to the current database time.
- Every actual state transition writes an audit event in the same D1 batch. Repeating an action does not create duplicate audit records.
- The monitor list now shows paused state and role-aware Pause/Resume, Edit and Delete actions. The detail view shows configured state and offers Pause/Resume to writable roles.
- No probe is run by either action. The API continues to report `executionEnabled: false`; secure outbound transport and the scheduled runner remain launch blockers.
- Five new D1-backed Worker API tests cover owner pause/idempotency/audit, member resume/due-work state, viewer denial, cross-tenant denial and archived-monitor rejection.
- The updated 115-test suite passed GitHub Actions run #175 on commit `a6cac79dcd3ccc2865629d93829d6e5cb0a782e8`.


## Read-only workspace API keys (2026-11-13)

- Added owner/admin-only API key creation, metadata listing and immediate revocation using the existing `api_keys` table. Secrets are generated from 256 bits of cryptographic randomness, stored only as SHA-256 hashes, shown once, and expire after 30, 90 or 365 days. A workspace is limited to 10 active keys.
- Added bearer authentication for read-only monitor and incident endpoints. Keys are scoped to one workspace, require the creator to remain a verified owner/admin, update last-used metadata, and cannot mutate monitors/incidents or access authentication/team endpoints. Internal incident timeline events are omitted from key-authenticated reads.
- Added an API-key management panel to the workspace app with role-aware access, create/revoke actions, one-time secret display and copy support.
- Added D1-backed integration tests for creation, one-time secret handling, hashing, usage tracking, revocation, workspace isolation, read-only enforcement, internal timeline filtering, expiry and role restrictions.
- Added a follow-up hardening change so an explicit bearer credential takes precedence over an ambient session cookie; an invalid bearer never falls back to a valid cookie. This keeps the read-only boundary intact when both credentials are present.
- GitHub Actions [CI run #178](https://github.com/learninghub44/zetuwatch/actions/runs/43377446617) completed successfully on commit `6edf934be79bd20e5efcc5ec5ee8c6702d7253e3`.
- Verified: TypeScript typecheck; inline browser JavaScript syntax check; SQLite validation (6 migrations, 16 required tables); Vitest (13 files, 121 tests), including 24 Worker API integration tests.
- Browser E2E, external-client acceptance, API key rotation and any write scopes remain open; the feature is not marked launch-complete.


## Status-page builder implementation update (2026-11-14)

- Added migration `0007_status_pages.sql` for tenant-owned pages, ordered monitor components, globally unique slugs, archive/publish state and database triggers enforcing same-workspace monitor membership.
- Added workspace APIs to list/create/update/publish/unpublish/archive pages. Only owners/admins can mutate; all workspace members can list/read; API keys are denied. Component lists are limited to 50 live monitors and every requested monitor is checked against the owning organization.
- Added an unauthenticated public read endpoint that returns published pages only. Its response is an allowlist and includes only explicitly public incident updates; raw target URLs, monitor IDs, workspace IDs and internal timeline notes are not returned.
- Added a responsive status-page builder to the workspace app and a separate public `status.html?slug=...` renderer. All database-backed strings are inserted as text nodes.
- The public page deliberately reports health as unknown and `monitoringEnabled: false` because the secure scheduled runner is not enabled. Publishing a page does not claim that any component is operational.
- Added D1-backed tests for tenant isolation, role enforcement, public-data minimization, publication/archive lifecycle, cross-tenant database-trigger rejection, final-component protection and automatic unpublishing when the last monitor is soft-deleted.
- GitHub Actions [CI run #182](https://github.com/learninghub44/zetuwatch/actions/runs/43568666409) completed successfully on head commit `612533f31ca69f058e07211b40ed7c643949a974` after a regression fix for monitor-deletion trigger side effects. Verified: TypeScript typecheck, inline browser JavaScript syntax across five HTML files, SQLite validation (7 migrations, 16 previously required tables; status-page tables were exercised by the new D1 integration tests), and Vitest (13 files, 129 tests).
- Browser E2E, responsive/keyboard/screen-reader acceptance, custom domains, subscriptions and public-page cache behavior remain future work. Status pages are implemented and CI-verified but not launch-complete.
- Follow-up main commit `a3bcb10bd7033d0ef8a93dd0d09020d8dbb25d59` adds `status_pages` and `status_page_monitors` to the migration validator's required-table set (18 total). The post-merge main-branch CI result for that validator change has not yet been observed.


### Probe-agent DNS resource-bound hardening (2026-11-18)

- Replaced the uncancelled DNS Promise timeout wrapper with a per-hostname Node resolver, one-attempt query policy and explicit cancellation when the shared A/AAAA deadline expires.
- Added tests for timeout cancellation, A-only/AAAA-only answers, resolver failures, mixed public/private answers, empty answers and invalid bounds.
- This is a security hardening slice only. The agent remains separate from the scheduler; full PR CI, real DNS/TLS tests, durable replay storage, per-tenant quotas and Worker-to-agent integration remain open.


### Probe-agent total deadline enforcement (2026-11-18)

- Recomputed the remaining total probe budget after DNS resolution and before every outbound socket.
- Skip the connection when DNS consumes the remaining budget; pass only the post-DNS remainder to the transport.
- Added deterministic tests proving a slow DNS adapter cannot extend the overall probe deadline. Full PR CI and live network/TLS verification remain pending.


### Probe-agent source-IP rate-limit memory bound (2026-11-20)

- Replaced the cleanup-only source-IP rate limiter with a hard 5,000-bucket cap. Expired entries are reclaimed before admitting a new IP; if all entries are still live, new IPs are rejected rather than allowing attacker-controlled source cardinality to grow memory without bound.
- Added an injectable-clock unit test for capacity rejection, expired-bucket reclamation and invalid limiter configuration.
- No dependency or deployment change. A standalone Node 22.16.0 harness for the limiter logic passed two focused tests; the committed repository test file and full probe-agent/repository CI still require execution on this branch, so do not treat this change as CI-verified.


## Gated scheduler dispatch implementation (2026-11-22)

- Added a D1 scheduler dispatcher that checks configuration before claiming work, claims at most 10 monitors per tick by default (hard dispatch maximum 15) and at most two per workspace, and executes no more than five probes concurrently by default to stay below Cloudflare Workers' six simultaneous outbound-connection limit.
- Added per-workspace fairness to the atomic claim query with a window-function rank and a count of unexpired leases across overlapping invocations. Each workspace is capped at two in-flight probes by default; the global claim helper maximum remains 25 and the dispatcher hard maximum is 15.
- Added migration `0008_scheduler_workspace_quota_index.sql` and a query-plan assertion in `scripts/check-migrations.py`; SQLite uses the covering index for per-workspace active-lease counts instead of scanning the monitor table.
- The dispatcher uses a 180-second lease. With at most five concurrent requests, a 15-job batch requires at most three 35-second Worker request waves (105 seconds) plus D1 finalization overhead, leaving a bounded recovery margin.
- Added token-checked retry deferral for probe-agent/network/configuration failures. These infrastructure failures do not create false target-down checks; valid agent results alone enter check history and the existing incident state machine.
- Extended the signed client/agent deadline consistently to the monitor API's 30-second maximum, with a 35-second Worker request bound.
- Added nine D1 integration tests for disabled and invalid configuration, workspace fairness across overlapping invocations, bounded concurrency/batch limits, real failed-result persistence, infrastructure retry deferral, malformed responses and stale lease ownership. Added Node tests for the 30-second upper bound.
- A one-minute Cron Trigger is declared in `wrangler.toml` for the shared notification/monitor handler. It dispatches at most five email deliveries first; the monitor dispatcher runs only when `PROBES_ENABLED=true` and valid HTTPS agent URL/shared-secret bindings are present. Those probe bindings are not set in the repository, so no customer probes run by default.
- These new tests have not yet run in GitHub Actions. The latest branch is not CI-verified; the monitoring loop and production launch gates remain unchecked.


## Email notification integration update (2026-11-22)

- Integrated the verified-self-email channel APIs, responsive Alerts UI, D1 outbox, retry/lease dispatcher and delivery history with the DNS-pinned probe-agent branch.
- Renumbered the notification migration to `0009_notification_outbox.sql`; `0008_scheduler_workspace_quota_index.sql` remains reserved for the scheduler index.
- Scheduler finalization now enqueues email deliveries in the same D1 batch as immutable incident lifecycle events (opened, monitoring, resolved and reopened). Customer-authored status changes and timeline notes enqueue only when explicitly public; the dispatcher rechecks visibility before sending.
- The shared one-minute scheduled handler dispatches up to five emails first, then conditionally runs bounded probes. The two batches execute sequentially to stay below the six simultaneous-open-connection limit.
- The Cron Trigger is declared in `wrangler.toml`, but no external resource has been created. Monitor probes remain disabled unless `PROBES_ENABLED=true` and valid HTTPS agent URL/shared-secret bindings are configured. Resend delivery is skipped without its sender/API configuration.
- Full CI, browser acceptance, live DNS/TLS verification and controlled Resend delivery remain outstanding. Do not mark email or monitoring launch gates complete.

## Probe-client timeout contract correction (2026-11-22)

- Aligned the Worker-compatible probe client with the scheduler and Node agent's 1,000–30,000 ms monitor timeout range. The previous 10,000 ms client ceiling caused monitors configured above 10 seconds to be rejected before dispatch and repeatedly deferred as infrastructure failures.
- Added a regression boundary: 30,000 ms is accepted, while 30,001 ms is rejected before any network request. The Worker-to-agent request deadline remains bounded to 35 seconds.
- The complete GitHub Actions run for the updated integration head is still required; this correction is not marked CI-verified.

## Scheduler lease-expiry finalization hardening (2026-11-22)

- Check finalization now requires both the original lease token and an unexpired lease at the recorded check timestamp. A worker returning after lease expiry cannot persist a check even if no later invocation has reclaimed the row yet.
- Recovery-monitoring, incident resolution and incident reopening transitions require the check row inserted by the same finalization batch. Expired or superseded results therefore cannot change incident state or enqueue lifecycle notifications.
- Added D1 integration coverage for expired successful and failed results against an existing recovery incident; both must leave the lease, check history, incident state and timeline unchanged.
- The exact SQL sequence was independently exercised against SQLite for both stale-success and stale-failure paths. The full Cloudflare Vitest/Worker CI run for the updated branch remains pending.

## Customer monitor execution-state accuracy (2026-11-22)

- Centralized the probe configuration gate and exposed it to the customer API. `executionEnabled` is true only when the operator explicitly enables probes and supplies a valid HTTPS agent endpoint plus a 32-byte shared secret; this reports configuration, not agent reachability or successful target health.
- Monitor list/detail APIs now derive paused, execution-disabled, awaiting-first-check, healthy, suspect, down and recovering states from persisted check rows and unresolved incidents. The UI displays these states and no longer tells customers that probes are disabled when the operator has configured the runner.
- Added a D1-backed API integration test covering list/detail/check-history/create responses, seven monitor states (including unknown when a timestamp has no check row), and enabled, disabled and invalid probe configuration. Unresolved down/recovering incidents remain visible when probe dispatch is disabled. Full GitHub Actions verification remains pending.


## Monitor freshness state correction (2026-11-23)

- Added a derived `check_delayed` state when an enabled monitor's persisted `next_check_at` is overdue by more than the greater of two minutes or two configured intervals. This prevents an old successful check from being displayed as current health when the scheduler is delayed.
- The state remains distinct from a confirmed incident: open incidents still take precedence, recent failed checks remain suspect, paused/disabled monitors retain their existing states, and no synthetic check or incident is created.
- Updated monitor list/detail UI with an amber "Check delayed" label and an explanation that the last stored result may be old.
- Added D1-backed API coverage for a delayed monitor with an old successful check, a delayed monitor awaiting its first check, and the monitor-detail response. Existing fresh healthy/awaiting, suspect, incident, disabled and paused states remain covered.
- The change has been committed to the monitoring integration pull request. The full GitHub Actions suite and browser E2E/accessibility checks must still pass before this state logic is treated as launch-verified.
