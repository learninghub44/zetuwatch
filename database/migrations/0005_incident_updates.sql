PRAGMA foreign_keys = ON;

-- Customer-authored timeline entries retain an optional actor reference.
-- If an account is later removed, the historical event remains attributable
-- only as a deleted account rather than being deleted with the user.
ALTER TABLE incident_events
  ADD COLUMN actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

-- Internal notes are workspace-only. Public updates may be consumed by a
-- future status-page publisher, but are not exposed publicly by this migration.
ALTER TABLE incident_events
  ADD COLUMN visibility TEXT NOT NULL DEFAULT 'internal'
  CHECK (visibility IN ('internal', 'public'));

CREATE INDEX IF NOT EXISTS idx_incident_events_visibility_time
  ON incident_events(incident_id, visibility, created_at, id);
