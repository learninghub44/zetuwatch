PRAGMA foreign_keys = ON;

-- Track consecutive healthy checks independently from the failure streak.
ALTER TABLE monitors ADD COLUMN consecutive_successes INTEGER NOT NULL DEFAULT 0
  CHECK (consecutive_successes >= 0);

-- A monitor may have at most one unresolved incident at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_one_active_per_monitor
  ON incidents(monitor_id) WHERE resolved_at IS NULL;

-- Incident timeline entries are append-only. Cascading deletion remains
-- available for an explicit monitor/account deletion workflow.
CREATE TRIGGER IF NOT EXISTS incident_events_prevent_update
BEFORE UPDATE ON incident_events
BEGIN
  SELECT RAISE(ABORT, 'INCIDENT_EVENTS_IMMUTABLE');
END;
