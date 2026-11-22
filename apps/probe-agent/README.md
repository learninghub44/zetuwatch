# ZetuWatch probe agent

This is the standalone Node.js egress service used to perform DNS-validated, IP-pinned HTTP/HTTPS monitor requests. It uses Node built-in modules only and requires Node.js 22.12 or later.

See [docs/PROBE_AGENT.md](../../docs/PROBE_AGENT.md) for the trust boundary, request signing, operational configuration, limits, tests and outstanding launch gates.

A gated D1 scheduler dispatcher now calls the signed Worker client with per-workspace claim quotas and bounded concurrency. The Worker has no Cron Trigger configured, and dispatch requires `PROBES_ENABLED=true`, a valid HTTPS `PROBE_AGENT_URL` and `PROBE_SHARED_SECRET`. These bindings are not configured in the repository; no customer probes run by default. Do not deploy or enable scheduled monitoring until the full CI, trusted TLS/DNS and Worker-to-agent-to-D1 launch gates pass.
