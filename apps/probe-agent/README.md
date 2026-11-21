# ZetuWatch probe agent

This is the standalone Node.js egress service used to perform DNS-validated, IP-pinned HTTP/HTTPS monitor requests. It uses Node built-in modules only and requires Node.js 22.12 or later.

See [docs/PROBE_AGENT.md](../../docs/PROBE_AGENT.md) for the trust boundary, request signing, operational configuration, limits, tests and outstanding launch gates.

The agent is not yet connected to the scheduler. Do not deploy or enable scheduled monitoring based solely on the existence of this service.
