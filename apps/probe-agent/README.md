# ZetuWatch probe agent

This is the standalone Node.js egress service used to perform DNS-validated, IP-pinned HTTP/HTTPS monitor requests. It uses Node built-in modules only and requires Node.js 22.12 or later.

See [docs/PROBE_AGENT.md](../../docs/PROBE_AGENT.md) for the trust boundary, request signing, operational configuration, limits, tests and outstanding launch gates.

A gated D1 scheduler dispatcher now calls the signed Worker client with per-workspace claim quotas and bounded concurrency. A one-minute Cron Trigger is declared for the shared scheduled handler. It dispatches email notifications first; monitor probes remain gated by `PROBES_ENABLED=true`, a valid HTTPS `PROBE_AGENT_URL` and `PROBE_SHARED_SECRET`. Those probe bindings are not configured in the repository, so no customer probes run by default. Do not deploy or enable scheduled monitoring until the full CI, trusted TLS/DNS and Worker-to-agent-to-D1 launch gates pass.


Production startup requires `PROBE_REPLAY_URL` pointing to the HTTPS Worker endpoint `/internal/probe-agent/replay`. The Worker and agent use the same `PROBE_SHARED_SECRET`; the Worker stores only SHA-256 nonce hashes in D1. See [docs/PROBE_AGENT.md](../../docs/PROBE_AGENT.md) before operating the service.
