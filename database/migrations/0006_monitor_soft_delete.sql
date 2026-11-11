PRAGMA foreign_keys = ON;

-- Deleting a monitor from the customer workspace is a reversible-in-principle
-- soft deletion: stop future work, retain checks/incidents/timelines for the
-- documented retention and export workflows, and record the actor.
ALTER TABLE monitors ADD COLUMN deleted_at TEXT;
ALTER TABLE monitors
  ADD COLUMN deleted_by TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_monitors_active_org
  ON monitors(organization_id, deleted_at, created_at);
