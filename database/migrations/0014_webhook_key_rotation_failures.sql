PRAGMA foreign_keys = ON;

-- Failed endpoint rotations are quarantined with a bounded retry schedule.
-- This prevents one malformed ciphertext row from monopolizing every small
-- scheduled batch while still retrying after an operator has corrected it.
CREATE TABLE IF NOT EXISTS webhook_key_rotation_failures (
  endpoint_id TEXT PRIMARY KEY REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  encryption_key_id TEXT NOT NULL CHECK (length(encryption_key_id) BETWEEN 1 AND 32),
  attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts BETWEEN 1 AND 20),
  retry_after TEXT NOT NULL,
  last_error_code TEXT NOT NULL CHECK (
    last_error_code IN (
      'WEBHOOK_ENCRYPTION_FORMAT_UNSUPPORTED',
      'WEBHOOK_ENDPOINT_AUTHENTICATION_FAILED',
      'ROW_ROTATION_FAILED'
    )
  ),
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webhook_key_rotation_failures_retry
  ON webhook_key_rotation_failures(retry_after, encryption_key_id, endpoint_id);

CREATE TRIGGER IF NOT EXISTS webhook_key_rotation_clear_on_endpoint_delete
AFTER UPDATE OF deleted_at ON webhook_endpoints
WHEN NEW.deleted_at IS NOT NULL
BEGIN
  DELETE FROM webhook_key_rotation_failures WHERE endpoint_id = NEW.id;
END;
