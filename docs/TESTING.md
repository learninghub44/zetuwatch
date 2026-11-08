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

## API integration coverage

- Missing sessions are rejected.
- Organization-scoped monitor listing rejects users outside the requested organization.
- Monitor detail and check-history reads reject cross-tenant IDs.
- Monitor creation cannot target an organization without membership.
- Members can create/read their own monitors but cannot delete them.
- Viewers can read but cannot create or update monitors.
- Team membership cannot be read across tenant boundaries.

These tests verify the Worker routes against D1's SQLite-compatible runtime. They do not replace production D1 verification, browser end-to-end tests, provider delivery tests or a security review of outbound network execution. No scheduled probes are enabled by this test setup.
