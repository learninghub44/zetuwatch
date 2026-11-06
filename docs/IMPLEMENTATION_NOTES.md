# Implementation notes

The current API is intentionally limited to health and a development probe preview. It does not yet create customer monitors, authenticate users, schedule jobs, send notifications or accept payments.

The probe preview is not intended to be exposed as a public arbitrary-URL proxy. Before public deployment, add authentication/rate limits or remove this route, then implement server-side SSRF protection with DNS resolution and network egress controls.

The initial schema is a starting point. Before production, add tenant-safe composite foreign keys where appropriate, retention/partition strategy, migration tests and a formal data deletion/export process.
