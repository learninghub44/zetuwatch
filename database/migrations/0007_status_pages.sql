PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS status_pages (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 80),
  slug TEXT NOT NULL COLLATE NOCASE UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  is_published INTEGER NOT NULL DEFAULT 0 CHECK (is_published IN (0, 1)),
  created_by TEXT REFERENCES users(id) ON DELETE SET NULL,
  published_at TEXT,
  archived_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_status_pages_org
  ON status_pages(organization_id, archived_at, created_at DESC);

CREATE TABLE IF NOT EXISTS status_page_monitors (
  page_id TEXT NOT NULL REFERENCES status_pages(id) ON DELETE CASCADE,
  monitor_id TEXT NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK (position >= 0),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (page_id, monitor_id),
  UNIQUE (page_id, position)
);

CREATE INDEX IF NOT EXISTS idx_status_page_monitors_monitor
  ON status_page_monitors(monitor_id, page_id);

-- A page may only contain live monitors owned by the same workspace.
-- Enforce this in SQLite as well as in the API so future code paths cannot
-- accidentally attach another tenant's monitor.
CREATE TRIGGER IF NOT EXISTS status_page_monitor_same_org_insert
BEFORE INSERT ON status_page_monitors
WHEN NOT EXISTS (
  SELECT 1
  FROM status_pages p
  JOIN monitors m ON m.id = NEW.monitor_id
  WHERE p.id = NEW.page_id
    AND p.organization_id = m.organization_id
    AND p.archived_at IS NULL
    AND m.deleted_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'STATUS_PAGE_MONITOR_TENANT_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS status_page_monitor_same_org_update
BEFORE UPDATE OF page_id, monitor_id ON status_page_monitors
WHEN NOT EXISTS (
  SELECT 1
  FROM status_pages p
  JOIN monitors m ON m.id = NEW.monitor_id
  WHERE p.id = NEW.page_id
    AND p.organization_id = m.organization_id
    AND p.archived_at IS NULL
    AND m.deleted_at IS NULL
)
BEGIN
  SELECT RAISE(ABORT, 'STATUS_PAGE_MONITOR_TENANT_MISMATCH');
END;
