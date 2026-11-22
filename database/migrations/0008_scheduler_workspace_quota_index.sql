-- Support the scheduler's per-workspace in-flight lease count without a
-- full monitor-table scan for every due candidate.
CREATE INDEX IF NOT EXISTS idx_monitors_org_active_leases
  ON monitors(organization_id, is_enabled, deleted_at, check_lease_token, check_lease_until);
