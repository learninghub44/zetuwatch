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

Store next-check timestamps in UTC. The current D1 claim layer uses a bounded `UPDATE` followed by a `SELECT` in one [D1 batch transaction](https://developers.cloudflare.com/d1/worker-api/d1-database/#batch). It leases only due, enabled monitors, defaults to 10 claims per batch and rejects limits above 25. A lease expires after a bounded interval so abandoned work can be reclaimed. The due timestamp is not advanced until the current lease owner finalizes a result.

Result finalization updates the monitor's last-check time, next due time and consecutive-failure count while appending one check row in the same batch. Every release/finalization is guarded by the lease token, preventing a stale worker from overwriting a newer claim. UTC SQL timestamps use a consistent SQLite format for due-time ordering; lease expiries use normalized ISO timestamps.

These are tested persistence primitives, not an active runner. No [Cron Trigger handler](https://developers.cloudflare.com/workers/runtime-apis/handlers/scheduled/) is configured and no customer target is probed while the pinned-IP HTTP/HTTPS transport remains unverified. Do not interpret a failed scheduler invocation as an outage at every customer endpoint.

## Incident policy

The D1 result finalizer currently implements a consecutive-check state machine. By default it opens an incident after two failures, moves the incident to `monitoring` after the first successful follow-up, resolves it after two consecutive successes, and returns it to `investigating` if a failure interrupts recovery. Failure and recovery thresholds are bounded and configurable. A partial unique index prevents more than one unresolved incident per monitor.

The check row, monitor counters and incident transition are written in the same D1 batch while the caller still owns the monitor lease. Timeline events are inserted only for state transitions; a database trigger rejects event updates. Monitor deletion still cascades incident history, so the timeline is not yet fully immutable across deletion. Add soft deletion and retention-aware export/deletion workflows before changing that claim.

This is tested persistence logic only. Incident list/detail routes, user-authored status updates, notification fan-out and live probe-driven incidents remain unimplemented.

## Evolution

D1 is the first low-cost deployment target, not a permanent constraint. Keep SQL and domain logic portable so a later move to managed PostgreSQL or dedicated workers does not change the public API.
