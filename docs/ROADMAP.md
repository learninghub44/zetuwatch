# Product roadmap

The product is built in vertical slices. A slice is complete only when UI, API, persistence, authorization, tests, documentation and operational visibility are present.

## Phase 0 — foundation
- [x] Public repository and project documentation
- [x] Initial D1 schema
- [x] Worker API health endpoint
- [x] Conservative HTTP probe foundation
- [x] Product scope and user journey specification
- [x] CI typecheck workflow added and verified in GitHub Actions
- [ ] Unit and integration test suite (71 tests across 8 files now pass in CI, including 9 D1-backed API integration tests plus an authentication lifecycle test for registration, verification, login, password reset and session revocation; scheduler, incident and payment lifecycle coverage remains)
- [x] Direct development-tool versions checked against current package releases and pinned
- [ ] Lockfile generation and clean-install verification

## Phase 1 — secure account foundation
- [ ] Authentication foundation: registration, email verification, password login/reset and opaque sessions are implemented; a D1-backed test now covers registration → verification → login → password reset → session revocation with email delivery stubbed; browser E2E, live provider delivery and security edge-case tests remain
- [ ] Invitation acceptance and full team/member management (member listing, role policy, invitations, acceptance, role changes, removal API and initial responsive team screen implemented; team member-list isolation, single-use concurrent invitation acceptance and concurrent owner demotion are covered by D1 integration tests; browser acceptance and real email delivery remain)
- [ ] Organization creation and basic membership checks exist; team-management API now enforces owner/admin/member/viewer policy and last-owner protection; monitor/team tenant boundaries, invitation consumption and concurrent owner protection pass D1-backed API tests, while broader route coverage remains
- [ ] Tenant-safe schema constraints and migration tests (two migrations pass the CI SQLite smoke-test and the API suite runs against isolated local D1; production-account D1 behavior remains unverified)
- [ ] Audit events and basic per-IP auth/monitor rate limits exist; broader abuse controls remain

## Phase 2 — first working monitoring loop
- [ ] Basic tenant-scoped monitor create/list/read/update/delete API and responsive setup screen implemented; 9 D1-backed API tests now cover core cross-tenant reads/creates, member/viewer permissions, single-use invitation acceptance and concurrent owner protection, while the full route matrix and browser acceptance remain
- [ ] Safe URL/egress policy including DNS/IP resolution/pinning, redirect-hop checks and DNS-rebinding defense
- [ ] Bounded scheduled runner and atomic due-work claiming
- [ ] HTTP/HTTPS checks, history and latency
- [ ] Incident confirmation, deduplication and recovery
- [ ] Verified email alerts and delivery history

## Phase 3 — complete customer experience
- [ ] Public marketing website, docs and pricing
- [ ] Multi-step sign-up and resumable onboarding
- [ ] Workspace overview and monitor list/create/delete screen implemented; full monitor detail, check history and real measurements remain
- [ ] Incident timeline and customer-facing updates
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

**Security boundary unchanged:** scheduled probes remain disabled. Customer-controlled URLs must not be executed until a reviewed egress design provides DNS/IP validation, redirect-hop validation, rebinding resistance, bounded network execution and abuse controls.
