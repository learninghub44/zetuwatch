# ZetuWatch

**Know before your customers do.**

ZetuWatch is an open-source website and API monitoring SaaS under active development. It is designed around Cloudflare Workers and D1 to keep the initial infrastructure footprint small while preserving a path to dedicated probe infrastructure as usage grows.

> **Project status: early development. Not production-ready.** Authentication groundwork and the public marketing/authentication screens exist, but monitor scheduling, secure egress, incidents, customer dashboard operations, billing and deployment verification remain incomplete. No uptime SLA is offered.

## Product direction

- HTTP/HTTPS website checks and API assertions
- Check history, response-time analytics and incident lifecycle
- Email and signed webhook notifications
- Public status pages and maintenance windows
- Teams, roles, API keys and organization workspaces
- Usage limits, subscription billing and optional add-ons

See [Product specification](docs/PRODUCT_SPEC.md), [UX flows](docs/UX_FLOWS.md) and [Roadmap](docs/ROADMAP.md).

## Current implementation

- Cloudflare Worker API with a health endpoint
- D1 base schema and auth/operations migration
- Email/password registration, email verification, login, logout and password-reset API routes
- Opaque hashed session tokens in HttpOnly cookies
- Basic D1-backed per-IP auth rate limits and exact-origin CORS
- Responsive marketing page and sign-in/registration/password-reset screens
- GitHub Actions typecheck workflow

The authentication foundation requires a configured Resend sender and app/API origins. See [Authentication setup](docs/AUTH_SETUP.md). It has not yet passed end-to-end browser and production integration testing.

## Architecture

- Cloudflare Workers for API and (planned) scheduled execution
- Cloudflare D1 for initial persistence
- TypeScript monitoring core
- Resend REST API for transactional email when configured
- GitHub Actions for CI

The project deliberately avoids Redis, a VPS and paid infrastructure dependencies at the beginning. Free-tier quotas and provider terms can change; validate current limits before launch.

## Repository layout

- `apps/api` — Cloudflare Worker API
- `apps/web` — public website and account screens
- `apps/monitor` — planned scheduled monitor runner
- `packages/monitoring-core` — URL validation and probe foundations
- `database/migrations` — D1 schema migrations
- `docs` — product, architecture, security, operations and onboarding documentation

## Local development

Requirements: Node.js 20+, npm and Wrangler.

```sh
npm install
npm run typecheck
npx wrangler d1 migrations apply zetuwatch --local
npm run dev:api
```

Copy `.dev.vars.example` to `.dev.vars` for local email provider secrets. Configure `PUBLIC_APP_URL` and the `api-base` meta tags in the web pages as described in [Authentication setup](docs/AUTH_SETUP.md). Never commit real credentials.

## Deploying

No Cloudflare resources have been created by this repository workflow and nothing has been deployed. Before deployment:

1. Create a D1 database in the intended Cloudflare account.
2. Replace the placeholder D1 database ID in `wrangler.toml`.
3. Configure Worker secrets and the production app origin.
4. Review and apply migrations to the intended database.
5. Run the test suite and security review.
6. Deploy the API and web app separately, then run authenticated smoke tests.

Do not expose an admin API or production database credentials publicly. Deployment requires explicit operator approval.

## Security

Customer-supplied monitor URLs are an SSRF risk. The current URL validator is only a preliminary syntax/host check. It does not resolve DNS or pin a validated IP, and therefore is **not sufficient to enable public probes**. A hardened egress architecture, redirect-hop validation, DNS rebinding defenses, response limits, rate limits and abuse controls must be implemented and reviewed before scheduled checks are enabled. See [SECURITY.md](SECURITY.md).

## Licensing

This repository is licensed under Apache-2.0. No UptimeFlare source code has been copied into the initial scaffold. If upstream code is incorporated later, retain its license, notices and required modification markings.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should be sent privately to maintainers rather than posted as public issues.
