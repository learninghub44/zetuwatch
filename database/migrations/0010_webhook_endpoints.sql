PRAGMA foreign_keys = ON;

-- Endpoint URLs and signing secrets are encrypted by the Worker before they
-- enter D1. This table stores only ciphertext, random AES-GCM nonces, a
-- non-secret hostname label, and a one-way destination hash.
CREATE TABLE IF NOT EXISTS webhook_endpoints (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  destination_host TEXT NOT NULL CHECK (length(destination_host) BETWEEN 1 AND 253),
  destination_hash TEXT NOT NULL CHECK (length(destination_hash) = 64),
  destination_ciphertext TEXT NOT NULL,
  destination_nonce TEXT NOT NULL,
  secret_ciphertext TEXT NOT NULL,
  secret_nonce TEXT NOT NULL,
  secret_last4 TEXT NOT NULL CHECK (length(secret_last4) = 4),
  encryption_key_version INTEGER NOT NULL DEFAULT 1 CHECK (encryption_key_version = 1),
  is_enabled INTEGER NOT NULL DEFAULT 0 CHECK (is_enabled IN (0, 1)),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  deleted_at TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_endpoints_org_destination
  ON webhook_endpoints(organization_id, destination_hash)
  WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_org_active
  ON webhook_endpoints(organization_id, created_at DESC)
  WHERE deleted_at IS NULL;
