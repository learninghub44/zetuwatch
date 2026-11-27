PRAGMA foreign_keys = ON;

-- Keep the ciphertext format version separate from the operator-managed
-- master-key identifier. Existing AES-256-GCM rows remain key id "v1" and
-- retain their original AAD context; new key ids use a key-id-bound context.
ALTER TABLE webhook_endpoints
  ADD COLUMN encryption_key_id TEXT NOT NULL DEFAULT 'v1'
  CHECK (
    length(encryption_key_id) BETWEEN 1 AND 32
    AND encryption_key_id NOT GLOB '*[^A-Za-z0-9_-]*'
  );

-- The scheduled re-encryption worker scans only active rows not encrypted
-- with the current key. Deleted rows have already had ciphertext scrubbed.
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_key_rotation
  ON webhook_endpoints(encryption_key_id, created_at, id)
  WHERE deleted_at IS NULL;
