# Product roadmap

The product is built in vertical slices. A slice is complete only when UI, API, persistence, authorization, tests, documentation and operational visibility are present.

## Phase 0 — foundation
- [x] Public repository and project documentation
- [x] Initial D1 schema
- [x] Worker API health endpoint
- [x] Conservative HTTP probe foundation
- [x] Product scope and user journey specification
- [x] CI typecheck workflow added and verified in GitHub Actions
- [ ] Unit and integration test suite (100 tests across 12 files pass in CI, including authentication, tenant/team and incident API isolation, SSRF policy/DNS, scheduler and incident lifecycle tests; payment lifecycle coverage, browser E2E and provider tests remain)
- [x] Direct development-tool versions checked against current package releases and pinned
- [ ] Lockfile generation and clean-install verification

## Phase 1 — secure account foundation
- [ ] Authentication foundation: registration, email verification, password login/reset and opaque sessions are implemented; a D1-backed test now covers registration → verification → login → password reset → session revocation with email delivery stubbed; browser E2E, live provider delivery and security edge-case tests remain
- [ ] Invitation acceptance and full team/member management (member listing, role policy, invitations, acceptance, role changes, removal API and initial responsive team screen implemented; team member-list isolation, single-use concurrent invitation acceptance and concurrent owner demotion are covered by D1 integration tests; browser acceptance and real email delivery remain)
- [ ] Organization creation and basic membership checks exist; team-management API now enforces owner/admin/member/viewer policy and last-owner protection; monitor/team tenant boundaries, invitation consumption and concurrent owner protection pass D1-backed API tests, while broader route coverage remains
- [ ] Tenant-safe schema constraints and migration tests (five migrations are present; the new incident-action migration still needs CI SQLite smoke-test verification and API/scheduler/incident suites run against isolated local D1; production-account D1 behavior remains unverified)
- [ ] Audit events and basic per-IP auth/monitor rate limits exist; broader abuse controls remain

## Phase 2 — first working monitoring loop
- [ ] Basic tenant-scoped monitor create/list/read/update/delete API and responsive setup screen implemented; 11 D1-backed API tests now cover monitor/team boundaries, member/viewer permissions, invitation/owner concurrency and tenant-scoped incident list/detail reads, while the full route matrix and browser acceptance remain
- [ ] Safe URL/egress policy: syntactic validation, dependency-free IPv4/IPv6 classification, mixed-answer rejection and a bounded Cloudflare DoH A/AAAA resolver are implemented as unit-testable components; the resolver is not connected to monitor execution, and validated-address pinning, redirect-hop checks and rebinding defense remain unimplemented
- [x] Atomic due-work claim leases and D1-backed check finalization primitive (bounded batches, lease expiry/reclaim, token ownership and check-history persistence are integration-tested; no Cron execution or real probes are enabled)
- [ ] Bounded scheduled runner / Cron Trigger integration (load, lag and retry behavior remain untested; real execution is blocked on hardened DNS-pinned egress)
- [ ] HTTP/HTTPS checks, history and latency
- [ ] Incident confirmation, deduplication and recovery (D1-backed finalization confirms, deduplicates, monitors, resolves and reopens incidents; tenant-scoped incident list/detail APIs now return the timeline to workspace members. Member/admin/owner incident status transitions, internal/public customer-authored timeline notes, actor attribution, audit writes and responsive controls are implemented; six D1-backed Worker API integration tests were added. Public updates are stored but not published, browser E2E/accessibility and notifications remain. Monitor deletion still cascades timeline data until a soft-delete/retention workflow exists.)
- [ ] Verified email alerts and delivery history

## Phase 3 — complete customer experience
- [ ] Public marketing website, docs and pricing
- [ ] Multi-step sign-up and resumable onboarding
- [ ] Workspace overview and monitor list/create/delete screen implemented; full monitor detail, check history and real measurements remain
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
- [ ] Cloudflare quotas, limits and costs validated against target load
- [ ] Production deployment and smoke tests completed

Do not mark a phase complete because files or mock screens exist. Verify behavior.


## Incident action implementation update (2026-11-11)

- Added migration `0005_incident_updates.sql` with optional timeline actor attribution, internal/public visibility and a visibility/time index.
- Added owner/admin/member-only incident status transitions with a guarded state machine, conflict handling for concurrent transitions, resolved timestamps, append-only timeline entries and audit events.
- Added owner/admin/member-only customer-authored timeline notes with a 500-character limit, control-character rejection and explicit internal/public visibility.
- Incident detail reads now include event visibility and actor display names when the account still exists.
- Added six D1-backed integration tests for authorship, visibility, status lifecycle, viewer denial, cross-tenant denial, validation and concurrent transitions.
- Added responsive incident detail controls. Public visibility is only a stored classification for a future status-page publisher; no public page is published by this change.
- CI verification of this new migration, API code, browser script and six tests is pending. The incident phase and production launch gates remain incomplete.

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
- This is the durable claim/finalization layer only. No Cron Trigger is configured, no probe is executed and no live measurement is written. Scheduled execution remains disabled until the DNS-pinned HTTP/HTTPS transport and complete SSRF/redirect/abuse controls are implemented and verified.


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
