# Security policy

## Reporting

Please do not publish exploitable vulnerabilities in public issues. Contact the repository maintainer privately through GitHub's security advisory feature.

## Current security posture

This project is an early development scaffold, not a hardened production service. Do not expose it to untrusted users or use it to monitor sensitive internal systems yet.

## Mandatory safeguards before public monitor creation

- Resolve hostnames and reject loopback, private, link-local, multicast, reserved and cloud metadata IP ranges.
- Validate every redirect destination and defend against DNS rebinding.
- Restrict allowed ports, protocols, request methods, headers and body sizes.
- Apply strict connection and total timeouts.
- Never forward user cookies or internal service credentials.
- Rate-limit monitor creation and check execution per account and globally.
- Keep D1, provider and signing secrets server-side.
- Redact authorization headers, query secrets and response bodies from logs.
- Add abuse reporting, account suspension and audit trails.

URL string checks alone are not sufficient SSRF protection. The current `runHttpProbe` implementation deliberately throws `PROBE_EGRESS_NOT_HARDENED` and performs no network request. The monitor API stores configuration only and reports `executionEnabled: false`. Do not remove this fail-closed guard until a dedicated egress design has been reviewed and tested against private-address DNS answers, rebinding, IPv4-mapped IPv6, redirect chains and metadata endpoints.
