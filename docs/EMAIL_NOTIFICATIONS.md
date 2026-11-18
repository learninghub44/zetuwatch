# Email notification setup

ZetuWatch sends incident notifications through a verified member-owned email channel and a durable D1 outbox. This first delivery slice supports email only; webhook and SMS destinations are not accepted by the API.

## Requirements

- A Resend account with an email-sending domain verified for the intended sender.
- A Resend API key with permission to send email.
- A sender identity on that verified domain.
- A public HTTPS application URL for links in notification messages.
- The D1 migrations, including `0008_notification_outbox.sql`, applied before enabling the scheduled dispatcher.

## Worker configuration

Configure these values in the target Worker environment:

- `RESEND_API_KEY`: store as a Worker secret. Do not add it to `wrangler.toml`, source control, browser code or logs.
- `EMAIL_FROM`: the verified sender, for example `ZetuWatch Alerts <alerts@your-verified-domain.example>`. This is configuration, not a credential.
- `PUBLIC_APP_URL`: the absolute public HTTPS origin of the customer application.

For local development, use Wrangler's local secrets/vars mechanism and a test sender. Do not use production credentials in local test fixtures.

The repository's Cron Trigger is configured for `*/1 * * * *` (every minute, UTC). Its `scheduled()` handler dispatches at most five email deliveries per invocation. It does not run website/API probes. Cloudflare documents that Cron Trigger changes may take several minutes to propagate after a deployment; no external trigger was created by this implementation.

## Customer setup

1. Sign in with a verified account.
2. Open Workspace → Alerts.
3. Add the account's own verified email address.
4. Keep the channel enabled to receive incident lifecycle messages.
5. Use Delivery history to inspect queued, sent or failed attempts.
6. Disable or remove the channel to stop future queued deliveries.

Workspace owners/admins can manage all channels. Members can manage their own channel. Viewers can inspect their own channel and delivery history but cannot change settings. An email channel cannot be configured for another person's address; invite that person to the workspace and have them add their own verified address.

## Retry and idempotency behavior

- A D1 row is created once per incident timeline event and email channel.
- The dispatcher claims a bounded batch with a 90-second lease.
- Each provider request uses a stable event/channel idempotency key.
- Retry delays are 30 seconds, 2 minutes, 10 minutes, 1 hour and 6 hours; at most six attempts are made.
- Resend's documented idempotency window is 24 hours. The configured retry schedule remains inside that window.
- Provider/network timeouts, rate limits and server failures are retried. Invalid payload/idempotency conflicts are marked failed.
- Disabling/removing a channel cancels queued rows. It cannot recall a message already accepted by Resend.

## Verification and limitations

CI uses mocked provider responses and isolated local D1. No live Resend request or mailbox delivery is part of the automated suite. Before launch, verify the sender/domain and API key in the intended account, perform a controlled real delivery, verify the recipient experience, exercise disable/removal, and confirm that delivery logs do not expose secrets or internal target URLs.

The current monitoring probe runner remains disabled. Email notifications can dispatch only for incident events that already exist; they do not imply that ZetuWatch is actively checking customer URLs.
