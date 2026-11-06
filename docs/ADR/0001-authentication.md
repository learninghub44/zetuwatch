# ADR 0001: Authentication foundation

- Status: Accepted for implementation
- Date: 2026-11-06

## Context

ZetuWatch needs email/password registration, email verification, password recovery, secure sessions, invitation acceptance and organization-aware authorization. The initial stack is Cloudflare Workers plus D1, and the project should avoid a paid identity service unless a real requirement forces one.

Authentication must not be improvised with custom password hashing, homemade session tokens or ad hoc verification links.

## Decision

Use Better Auth with its built-in Cloudflare D1 support as the first authentication foundation.

- Use the stable 1.7 release line, pinned to 1.7.18 or a newer reviewed patch in that line.
- Do not use the 1.8 beta line for production.
- Enable email/password sign-up and require email verification before creating an authenticated session.
- Configure password reset and verification email callbacks through a server-side email adapter.
- Keep Better Auth's generated schema in its own migration, separate from application-owned tables.
- Use secure, HttpOnly, SameSite cookies; configure trusted origins and the production base URL explicitly.
- Keep the Better Auth secret and email provider credentials in Worker secrets, never in source control.
- Implement ZetuWatch organization membership and roles with explicit server-side authorization checks. Authentication alone does not grant access to a tenant.
- Avoid adding social login until a provider is selected and its OAuth credentials are available.

## Rationale

Better Auth is MIT-licensed, framework-agnostic, supports email/password and verification flows, and documents first-class D1 support. Its D1 adapter uses D1 batch operations; D1 does not provide interactive transactions, so workflows requiring cross-record atomicity must be designed around supported batch semantics and tested.

A security release published in November 2026 fixed multiple advisories in the 1.7 line. Pin a patched stable release and review subsequent advisories before each deployment.

## Email delivery

Use a small provider adapter that calls the Resend HTTP API from the Worker. This avoids SMTP socket complexity and keeps the provider replaceable. Do not send verification/reset messages until a sender domain and API key have been configured. Do not log tokens or full verification URLs.

Required secrets/configuration before live email verification:
- Better Auth secret (at least 32 random bytes, generated securely)
- Resend API key
- Verified sender address/domain
- Canonical application origin and allowed trusted origins

## Consequences

Positive:
- No paid auth vendor is required for the initial deployment.
- Password storage, session lifecycle, verification and reset flows use a maintained auth library.
- D1 remains the initial persistence layer.

Constraints:
- The generated auth schema and current application schema need an explicit migration plan.
- D1 batch behavior and auth callbacks require integration tests in Workers-compatible runtime.
- Live email verification cannot be tested until Resend credentials and a verified sender are supplied.
- Tenant isolation still requires separate organization-scoped data access helpers and tests.
