PRAGMA foreign_keys = ON;

-- Durable webhook event outbox. Only enabled, non-deleted endpoints receive
-- new events. The outbox stores references, never destination URLs or secrets.
CREATE TABLE IF NOT EXISTS webhook_deliveries (
  id TEXT PRIMARY KEY,
  organization_id TEXT NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  endpoint_id TEXT NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL REFERENCES incident_events(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'queued'
    CHECK (status IN ('queued', 'sent', 'failed', 'cancelled')),
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
  next_attempt_at TEXT,
  lease_token TEXT,
  lease_until TEXT,
  response_status INTEGER CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  last_error_code TEXT,
  delivered_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (event_id, endpoint_id),
  CHECK ((lease_token IS NULL AND lease_until IS NULL) OR
         (lease_token IS NOT NULL AND lease_until IS NOT NULL)),
  CHECK (status <> 'queued' OR next_attempt_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
  ON webhook_deliveries(status, next_attempt_at, lease_until, created_at, id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_org_time
  ON webhook_deliveries(organization_id, created_at DESC, id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint_time
  ON webhook_deliveries(endpoint_id, created_at DESC, id);

-- One row per actual attempt, including a started row that can be marked
-- abandoned when its lease expires. Completed attempt rows are immutable.
CREATE TABLE IF NOT EXISTS webhook_delivery_attempts (
  id TEXT PRIMARY KEY,
  delivery_id TEXT NOT NULL REFERENCES webhook_deliveries(id) ON DELETE CASCADE,
  attempt_number INTEGER NOT NULL CHECK (attempt_number BETWEEN 1 AND 8),
  status TEXT NOT NULL CHECK (status IN ('started', 'sent', 'retry', 'failed', 'abandoned')),
  response_status INTEGER CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  error_code TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  UNIQUE (delivery_id, attempt_number)
);

CREATE INDEX IF NOT EXISTS idx_webhook_delivery_attempts_delivery_time
  ON webhook_delivery_attempts(delivery_id, attempt_number DESC);

-- Enforce tenant and event ownership even for future code paths that bypass
-- the current API/dispatcher.
CREATE TRIGGER IF NOT EXISTS webhook_delivery_tenant_guard
BEFORE INSERT ON webhook_deliveries
WHEN NOT EXISTS (
  SELECT 1
  FROM webhook_endpoints e
  JOIN incidents i ON i.id = NEW.incident_id
  JOIN monitors m ON m.id = i.monitor_id
  JOIN incident_events ie ON ie.id = NEW.event_id AND ie.incident_id = i.id
  WHERE e.id = NEW.endpoint_id
    AND e.organization_id = NEW.organization_id
    AND m.organization_id = NEW.organization_id
)
BEGIN
  SELECT RAISE(ABORT, 'WEBHOOK_DELIVERY_TENANT_MISMATCH');
END;

CREATE TRIGGER IF NOT EXISTS webhook_delivery_identity_immutable
BEFORE UPDATE OF organization_id, endpoint_id, incident_id, event_id ON webhook_deliveries
WHEN NEW.organization_id <> OLD.organization_id
  OR NEW.endpoint_id <> OLD.endpoint_id
  OR NEW.incident_id <> OLD.incident_id
  OR NEW.event_id <> OLD.event_id
BEGIN
  SELECT RAISE(ABORT, 'WEBHOOK_DELIVERY_IDENTITY_IMMUTABLE');
END;

-- Every successful lease claim increments attempt_count. The trigger creates
-- the attempt log in the same atomic D1 statement and marks an expired
-- in-progress attempt abandoned before opening its replacement.
CREATE TRIGGER IF NOT EXISTS webhook_delivery_attempt_started
AFTER UPDATE OF attempt_count ON webhook_deliveries
WHEN NEW.attempt_count > OLD.attempt_count AND NEW.lease_token IS NOT NULL
BEGIN
  UPDATE webhook_delivery_attempts
  SET status = 'abandoned',
      error_code = 'LEASE_EXPIRED',
      completed_at = NEW.updated_at
  WHERE delivery_id = NEW.id AND status = 'started';

  INSERT INTO webhook_delivery_attempts (
    id, delivery_id, attempt_number, status, started_at
  ) VALUES (
    lower(hex(randomblob(16))), NEW.id, NEW.attempt_count, 'started', NEW.updated_at
  );
END;

CREATE TRIGGER IF NOT EXISTS webhook_delivery_attempts_append_only
BEFORE UPDATE ON webhook_delivery_attempts
WHEN OLD.status <> 'started' OR NEW.status = 'started'
BEGIN
  SELECT RAISE(ABORT, 'WEBHOOK_DELIVERY_ATTEMPTS_IMMUTABLE');
END;

-- Event fan-out is performed by SQLite in the same transaction as the
-- incident timeline insert. Internal customer-authored notes/status updates
-- are never queued. Endpoint activation remains a separate, gated operation.
CREATE TRIGGER IF NOT EXISTS webhook_delivery_enqueue_after_event
AFTER INSERT ON incident_events
BEGIN
  INSERT OR IGNORE INTO webhook_deliveries (
    id, organization_id, endpoint_id, incident_id, event_id, status,
    attempt_count, next_attempt_at, created_at, updated_at
  )
  SELECT
    lower(hex(randomblob(16))), m.organization_id, e.id, i.id, NEW.id, 'queued',
    0, strftime('%Y-%m-%dT%H:%M:%fZ', NEW.created_at), NEW.created_at, NEW.created_at
  FROM incidents i
  JOIN monitors m ON m.id = i.monitor_id
  JOIN webhook_endpoints e
    ON e.organization_id = m.organization_id
    AND e.is_enabled = 1
    AND e.deleted_at IS NULL
  WHERE i.id = NEW.incident_id
    AND (
      NEW.event_type NOT IN ('incident.update', 'incident.status_changed')
      OR NEW.visibility = 'public'
    );
END;
