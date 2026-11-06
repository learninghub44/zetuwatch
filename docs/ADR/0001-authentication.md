# ADR 0001: Authentication library evaluation

- Status: Deferred; not implemented
- Date: 2026-11-06

## Context

ZetuWatch needs email/password registration, email verification, password recovery, secure sessions, invitation acceptance and organization-aware authorization. The initial stack is Cloudflare Workers plus D1, and the project should avoid a paid identity service unless a real requirement forces one.

Authentication must not be improvised with custom password hashing, homemade session tokens or ad hoc verification links.

## Evaluated option: Better Auth

Better Auth is MIT-licensed, framework-agnostic, supports email/password and verification flows, and documents first-class D1 support. The stable 1.7.18 release is available; the 1.7 line received a security release in November 2026 addressing multiple advisories. D1 uses batch operations and does not provide interactive transactions, so multi-record workflows need explicit atomicity tests.

Official references:
- https://better-auth.com/docs/installation
- https://better-auth.com/docs/authentication/email-password
- https://better-auth.com/blog/security-release-2026-11-03

## Current repository implementation

The current Worker API contains a first-party interim authentication implementation:
- PBKDF2-HMAC-SHA-256 password hashes with per-user random salts;
- one-time email verification and password-reset tokens stored as SHA-256 hashes;
- opaque random session tokens stored as hashes and delivered in HttpOnly cookies;
- D1-backed per-IP rate limiting;
- Resend REST API integration for verification and password-reset email.

This implementation is not Better Auth. It has not passed complete security review, concurrency/abuse testing or browser end-to-end testing. It must not be described as production-ready.

## Decision and next step

Do not add Better Auth dependencies or claim Better Auth is integrated until a migration plan is implemented and tested. Before public launch, compare the interim implementation against Better Auth's maintained auth/session flows and either:

1. migrate to a patched stable Better Auth release with a separately versioned schema and tested D1 batch semantics; or
2. retain the first-party implementation only after independent security review, password/session/token tests, CSRF/origin tests, rate-limit abuse tests and recovery-flow integration tests pass.

Whichever option is selected must enforce email verification before authenticated access, secure cookie settings, trusted origins, token expiry/one-use semantics, session revocation, email enumeration resistance and auditability.

## Required live configuration

- At least 32 random bytes for the auth signing secret if required by the selected implementation.
- Resend API key with sending-only permission.
- Verified sender address/domain.
- Canonical application origin and explicit trusted origins.

Keep all credentials in Worker secrets, never in source control. Do not log passwords, tokens, full verification URLs or sensitive message content.
