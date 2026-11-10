PRAGMA foreign_keys = ON;

-- A monitor remains due until its check is durably finalized. The lease makes
-- claiming atomic across overlapping Cron Trigger invocations and allows
-- abandoned work to be reclaimed after the bounded lease expires.
ALTER TABLE monitors ADD COLUMN check_lease_token TEXT;
ALTER TABLE monitors ADD COLUMN check_lease_until TEXT;
ALTER TABLE monitors ADD COLUMN last_claimed_at TEXT;

CREATE INDEX IF NOT EXISTS idx_monitors_claimable
  ON monitors(is_enabled, next_check_at, check_lease_until);
