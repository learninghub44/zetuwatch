# Authentication setup

This repository now contains a first-party email/password authentication foundation for Cloudflare Workers and D1.

## Implemented endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/auth/register` | Create user + owner workspace and send verification email |
| POST | `/auth/verify` | Consume a one-time email verification token |
| POST | `/auth/resend-verification` | Send a fresh verification link without revealing account existence |
| POST | `/auth/login` | Verify password and create an opaque server-side session |
| POST | `/auth/logout` | Revoke current session |
| GET | `/auth/me` | Return signed-in user and workspace memberships |
| POST | `/auth/password-reset/request` | Request a password reset (generic response) |
| POST | `/auth/password-reset/confirm` | Consume reset token, change password and revoke sessions |

Passwords use PBKDF2-HMAC-SHA-256 with 310,000 iterations and a random 128-bit salt. Passwords are never stored in plaintext. Session and one-time tokens are random high-entropy values; only SHA-256 token hashes are stored in D1. Sessions are held in HttpOnly, SameSite=Strict cookies and expire after 30 days. Production cookies use Secure.

## Required configuration

1. Create a Resend account and verify a sender domain.
2. Create a Resend API key with sending permission only.
3. Set Worker secrets (never commit them):

```sh
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put EMAIL_FROM
```

Use a sender such as `ZetuWatch <notifications@your-verified-domain.example>`. The sender domain must be verified with the email provider.

4. Set `PUBLIC_APP_URL` in Worker configuration to the exact origin hosting `apps/web` (scheme + host, no path). It is used to build email links and validate browser origins.
5. In `apps/web/auth.html`, `apps/web/app.html` and `apps/web/reset-password.html`, change the `api-base` meta value from `/api` to the HTTPS API origin when the API is hosted separately, for example `https://api.your-domain.example`. The API sends credentialed CORS headers only to the configured app origin.
6. Serve the web files over HTTPS in production. Keep the app and API under the same registrable site where possible so SameSite=Strict cookies work in browser fetch requests.

For local development, configure a local sender/domain supported by your Resend account and set the app/API origins consistently. Do not test real email delivery until the sender domain is verified.

## Migration and local setup

```sh
npm install
npx wrangler d1 migrations apply zetuwatch --local
npm run dev:api
```

Apply migrations to a remote database only after reviewing the target account and database ID. The repository currently contains a placeholder D1 database ID; no production database has been created by this project.

## Security and remaining work

- The API uses an exact-origin allowlist for browser requests and rejects disallowed mutation origins. Requests without an Origin header remain available for non-browser clients; those clients must use a future API-key or other explicit authentication mechanism before accessing customer resources.
- Login and registration endpoints have a basic D1-backed per-IP rate limiter. Add edge-level WAF/rate limiting and account-keyed abuse controls before public launch.
- Email delivery errors are not logged with message content. Registration responses are intentionally generic to avoid revealing whether an address already has an account. Provider delivery webhooks, bounce/suppression handling and retry queue are not implemented yet.
- Multi-factor authentication, passkeys, OAuth, account recovery support workflows and session-management UI are not implemented.
- Workspace creation is currently one owner membership per new account. Full invitation acceptance and role-management APIs remain to be built.
- Password-reset and verification tokens are one-use and expire, but periodic cleanup of expired tokens and sessions is still required.
- A successful typecheck, migration test and end-to-end browser test are still required before treating this as production-ready.
