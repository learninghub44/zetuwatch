# ZetuWatch

**Website, API and cron monitoring for teams that want to know before their customers do.**

ZetuWatch is an open-source, self-hostable monitoring platform. The initial release is designed to run on Cloudflare's free-tier services where practical, with a path to dedicated infrastructure as usage grows.

> Project status: early foundation. This repository is not yet production-ready and does not promise an uptime SLA.

## Initial scope

- HTTP/HTTPS endpoint checks
- API checks with method, expected status and response-time tracking
- SSL certificate expiry visibility
- Cron/heartbeat monitoring (planned after the first HTTP monitor flow)
- Incident lifecycle and email notifications (planned)
- Public status pages, teams, billing and customer dashboard (planned)

## Architecture direction

- Cloudflare Workers for API and scheduled execution
- Cloudflare D1 for initial persistence
- Cron Triggers for scheduled checks
- TypeScript shared monitoring core
- Resend or another configured email provider for outbound notifications (optional; not required for local development)

The first release deliberately avoids Redis, a VPS, and paid infrastructure dependencies. Free-tier quotas and provider terms can change; validate current limits before launch.

## Repository layout

- `apps/api` — Worker API
- `apps/monitor` — scheduled monitor runner
- `packages/monitoring-core` — URL validation and probe logic
- `database` — D1 schema and migrations
- `docs` — architecture, security, operations and roadmap

## Local development

Requirements: Node.js 20+, npm, and Wrangler.

```bash
npm install
npm run typecheck
npm run dev:api
```

Copy `.dev.vars.example` to `.dev.vars` only if local secrets are needed. Never commit real credentials.

## Deploying

1. Create a Cloudflare D1 database.
2. Update the D1 database ID in `wrangler.toml`.
3. Apply migrations with `npx wrangler d1 migrations apply zetuwatch --local`, then use `--remote` after configuring the production database.
4. Deploy the Worker with `npm run deploy`.
5. Configure Cron Triggers in the Cloudflare dashboard or Wrangler configuration.

Do not expose an admin API or production database credentials publicly.

## Security

Customer-supplied URLs are an SSRF risk. The initial URL validation is intentionally conservative but is not a complete production SSRF boundary. Before enabling public user-created monitors, add DNS/IP resolution checks, redirect-by-redirect destination validation, egress restrictions, rate limits, response-size caps and abuse controls. See [SECURITY.md](SECURITY.md).

## Open-source licensing

This repository is licensed under Apache-2.0. No UptimeFlare source code has been copied into this initial scaffold. If upstream code is incorporated later, retain its Apache-2.0 license, notices and required modification markings.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports should be sent privately to the maintainers rather than posted as public issues.
