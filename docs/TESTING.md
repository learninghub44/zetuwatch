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

## API integration coverage (9 D1-backed tests)

- Missing sessions are rejected.
- Organization-scoped monitor listing rejects users outside the requested organization.
- Monitor detail and check-history reads reject cross-tenant IDs.
- Monitor creation cannot target an organization without membership.
- Members can create/read their own monitors but cannot delete them.
- Viewers can read but cannot create or update monitors.
- Team membership cannot be read across tenant boundaries.
- A team invitation is consumed at most once when two acceptance requests race; only one membership and one acceptance audit event are created.
- Concurrent owner demotions cannot remove the final workspace owner.

The full CI suite currently passes 95 tests across 11 files, including the 9 API integration tests, authentication lifecycle test and six scheduler integration tests. These tests verify Worker routes and scheduler persistence against D1's SQLite-compatible runtime. They do not replace production D1 verification, browser end-to-end tests, provider delivery tests or a security review of outbound network execution. No scheduled probes are enabled by this test setup.


## Scheduler integration coverage (6 D1-backed tests)

- Claims only enabled monitors whose due time has arrived, in deterministic order, and respects the caller's bounded batch size.
- Two overlapping claim calls cannot claim the same monitor.
- Expired leases can be reclaimed; an old lease token cannot release a newer worker's claim.
- Result finalization appends one check and advances the next-check time only for the current lease owner.
- Failed checks increment the consecutive-failure count; successful checks reset it.
- Invalid batch limits, lease durations and check-result fields are rejected.

These tests use isolated local D1. They do not invoke a Cron Trigger, contact customer URLs or assert production scheduler throughput/lag.
