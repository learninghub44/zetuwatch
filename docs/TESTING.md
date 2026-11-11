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

## API integration coverage (11 D1-backed tests)

- Missing sessions are rejected.
- Organization-scoped monitor listing rejects users outside the requested organization.
- Monitor detail and check-history reads reject cross-tenant IDs.
- Monitor creation cannot target an organization without membership.
- Members can create/read their own monitors but cannot delete them.
- Viewers can read but cannot create or update monitors.
- Team membership cannot be read across tenant boundaries.
- A team invitation is consumed at most once when two acceptance requests race; only one membership and one acceptance audit event are created.
- Concurrent owner demotions cannot remove the final workspace owner.
- Incident lists require workspace membership and return only incidents belonging to that tenant.
- Incident detail and timeline reads reject a foreign-tenant incident ID.

The last previously verified CI suite passed 100 tests across 12 files, including the 11 API integration tests, authentication lifecycle test, six scheduler integration tests and three incident lifecycle integration tests. The incident-action slice adds six D1-backed tests in a new file (106 tests across 13 files are now defined); CI verification of the new migration, API, browser script and tests is pending. These tests verify Worker routes and scheduler/incident persistence against D1's SQLite-compatible runtime. They do not replace production D1 verification, browser end-to-end tests, provider delivery tests or a security review of outbound network execution. No scheduled probes are enabled by this test setup.


## Scheduler integration coverage (6 D1-backed tests)

- Claims only enabled monitors whose due time has arrived, in deterministic order, and respects the caller's bounded batch size.
- Two overlapping claim calls cannot claim the same monitor.
- Expired leases can be reclaimed; an old lease token cannot release a newer worker's claim.
- Result finalization appends one check and advances the next-check time only for the current lease owner.
- Failed checks increment the consecutive-failure count; successful checks reset it.
- Invalid batch limits, lease durations and check-result fields are rejected.

These tests use isolated local D1. They do not invoke a Cron Trigger, contact customer URLs or assert production scheduler throughput/lag.


## Incident lifecycle integration coverage (3 D1-backed tests)

- An incident is opened only after the configured consecutive-failure threshold; repeated failures keep one active incident and do not duplicate the open event.
- The first successful check moves the active incident to monitoring; the configured recovery threshold resolves it.
- A failure during recovery reopens the same incident rather than creating a second active incident.
- Database updates to incident timeline events are rejected by the migration trigger.

## Incident action integration coverage (6 D1-backed tests)

- Members can append internal and public timeline notes; the API returns actor attribution and visibility.
- Members can advance an incident through the supported investigation, identified, monitoring and resolved states.
- A resolved incident rejects later customer-authored updates.
- Viewers cannot add notes or change incident status.
- Cross-tenant incident mutations are denied without appending timeline or audit records.
- Invalid transitions, empty/oversized/control-character messages and unsupported visibility values are rejected.
- Concurrent status transitions append only one event; the stale request receives a conflict response.

These tests exercise the actual Worker entrypoint against isolated D1. Public visibility is stored for future status-page publishing but does not publish an external page. Notification fan-out, retention/deletion semantics and live probe-driven incidents remain untested.


## Browser script syntax validation

CI runs `npm run check:inline-js`, which parses (but does not execute) inline JavaScript in each HTML file under `apps/web`. The current verified run parsed four scripts across four HTML files. This catches syntax errors in the static HTML application but is not a substitute for browser E2E, responsive-layout, keyboard-navigation or accessibility testing.
