PRAGMA foreign_keys = ON;

-- Email channels belong to a verified workspace member. A channel is only
-- created for that member's own verified account address; arbitrary
-- destinations and webhook URLs are not accepted by the first delivery slice.
ALTER TABLE notification_channels
  ADD COLUMN created_by TEXT REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE notification_channels
  ADD COLUMN verified_at TEXT;
ALTER TABLE notification_channels
  ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_channels_email_destination
  ON notification_channels(organization_id, lower(destination))
  WHERE channel_type = 'email';
CREATE INDEX IF NOT EXISTS idx_notification_channels_creator
  ON notification_channels(organization_id, created_by, is_enabled);

-- Extend the existing delivery log into a durable outbox. The incident event
-- is the idempotency key: one email delivery per channel and immutable event.
ALTER TABLE notification_deliveries
  ADD COLUMN event_id TEXT REFERENCES incident_events(id) ON DELETE SET NULL;
ALTER TABLE notification_deliveries
  ADD COLUMN event_type TEXT;
ALTER TABLE notification_deliveries
  ADD COLUMN recipient_email TEXT;
ALTER TABLE notification_deliveries
  ADD COLUMN lease_token TEXT;
ALTER TABLE notification_deliveries
  ADD COLUMN lease_until TEXT;
ALTER TABLE notification_deliveries
  ADD COLUMN updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP;

CREATE UNIQUE INDEX IF NOT EXISTS idx_notification_deliveries_event_channel
  ON notification_deliveries(event_id, channel_id)
  WHERE event_id IS NOT NULL AND channel_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_due
  ON notification_deliveries(status, next_attempt_at, lease_until, created_at);
CREATE INDEX IF NOT EXISTS idx_notification_deliveries_org_time
  ON notification_deliveries(organization_id, created_at DESC);
