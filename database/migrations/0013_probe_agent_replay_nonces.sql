PRAGMA foreign_keys = ON;

-- The probe agent claims each signed request nonce in the control-plane D1
-- database before opening any customer-target socket. Only a one-way hash is
-- persisted; raw nonces and signed request bodies are never stored.
CREATE TABLE IF NOT EXISTS probe_agent_replay_nonces (
  nonce_hash TEXT PRIMARY KEY
    CHECK (length(nonce_hash) = 64 AND nonce_hash NOT GLOB '*[^a-f0-9]*'),
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  CHECK (expires_at > created_at)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_probe_agent_replay_nonces_expiry
  ON probe_agent_replay_nonces(expires_at);
