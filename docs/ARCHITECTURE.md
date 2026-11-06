# Architecture

## Initial deployment

A Cloudflare Worker exposes the API and a Cron Trigger starts scheduled work. D1 stores accounts, monitors, check results and incidents. The initial design avoids Redis and a continuously running server.

## Boundaries

- API: validates requests and owns customer-facing operations.
- Scheduler: selects due monitors and dispatches bounded probe work.
- Monitoring core: protocol-specific probe logic and safety checks.
- Database: durable source of truth; check history is append-only.
- Notifications: provider adapters; failures must not erase incident state.

## Multi-tenant rules

Every customer-owned row must carry an organization identifier. Authorization must be enforced on the server for every read and write. Never trust an organization ID supplied by a browser without checking membership.

## Scheduling

Store next-check timestamps in UTC. Claim due work atomically, cap work per invocation and make check processing idempotent. Do not interpret a failed scheduler invocation as an outage at every customer endpoint.

## Incident policy

A single failed check marks a monitor as suspect. Confirm an incident only after consecutive failures or a configured failure window. Recover only after successful follow-up checks. Persist each state transition as an incident event.

## Evolution

D1 is the first low-cost deployment target, not a permanent constraint. Keep SQL and domain logic portable so a later move to managed PostgreSQL or dedicated workers does not change the public API.
