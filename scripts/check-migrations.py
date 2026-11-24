from pathlib import Path
import sqlite3

ROOT = Path(__file__).resolve().parents[1]
MIGRATIONS = sorted((ROOT / "database" / "migrations").glob("*.sql"))

def main() -> None:
    if not MIGRATIONS:
        raise SystemExit("No SQL migrations found")
    db = sqlite3.connect(":memory:")
    db.execute("PRAGMA foreign_keys = ON")
    for migration in MIGRATIONS:
        print(f"Applying {migration.name}")
        db.executescript(migration.read_text(encoding="utf-8"))

    required = {
        "users", "organizations", "organization_members", "monitors",
        "monitor_checks", "incidents", "incident_events", "notification_channels",
        "audit_logs", "auth_tokens", "auth_sessions", "auth_rate_limits",
        "organization_invitations", "api_keys", "notification_deliveries",
        "maintenance_windows", "status_pages", "status_page_monitors", "webhook_endpoints",
    }
    existing = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    )}
    missing = required - existing
    if missing:
        raise SystemExit(f"Missing tables: {', '.join(sorted(missing))}")

    monitor_indexes = {row[1] for row in db.execute("PRAGMA index_list(monitors)")}
    if "idx_monitors_org_active_leases" not in monitor_indexes:
        raise SystemExit("Missing idx_monitors_org_active_leases")

    lease_query_plan = list(db.execute(
        """EXPLAIN QUERY PLAN SELECT COUNT(*) FROM monitors
           WHERE organization_id = ? AND is_enabled = 1 AND deleted_at IS NULL
             AND check_lease_token IS NOT NULL AND check_lease_until > ?""",
        ("migration-check", "2026-11-22T06:30:00.000Z"),
    ))
    if not any("idx_monitors_org_active_leases" in row[3] for row in lease_query_plan):
        raise SystemExit("Workspace active-lease query does not use idx_monitors_org_active_leases")

    user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    for column in ("password_hash", "email_verified_at", "updated_at"):
        if column not in user_columns:
            raise SystemExit(f"Missing users.{column}")

    channel_columns = {row[1] for row in db.execute("PRAGMA table_info(notification_channels)")}
    for column in ("created_by", "verified_at", "updated_at"):
        if column not in channel_columns:
            raise SystemExit(f"Missing notification_channels.{column}")
    delivery_columns = {row[1] for row in db.execute("PRAGMA table_info(notification_deliveries)")}
    for column in ("event_id", "event_type", "recipient_email", "channel_created_by", "lease_token", "lease_until", "updated_at"):
        if column not in delivery_columns:
            raise SystemExit(f"Missing notification_deliveries.{column}")
    required_notification_indexes = {
        "idx_notification_channels_email_destination", "idx_notification_channels_creator",
        "idx_notification_deliveries_event_channel", "idx_notification_deliveries_due",
        "idx_notification_deliveries_org_time", "idx_notification_deliveries_channel_creator",
    }
    existing_indexes = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'index'")}
    missing_notification_indexes = required_notification_indexes - existing_indexes
    if missing_notification_indexes:
        raise SystemExit(f"Missing notification indexes: {', '.join(sorted(missing_notification_indexes))}")

    webhook_columns = {row[1] for row in db.execute("PRAGMA table_info(webhook_endpoints)")}
    for column in (
        "destination_host", "destination_hash", "destination_ciphertext", "destination_nonce",
        "secret_ciphertext", "secret_nonce", "secret_last4", "encryption_key_version",
        "is_enabled", "created_by", "deleted_at",
    ):
        if column not in webhook_columns:
            raise SystemExit(f"Missing webhook_endpoints.{column}")
    webhook_indexes = {row[1] for row in db.execute("PRAGMA index_list(webhook_endpoints)")}
    for index in ("idx_webhook_endpoints_org_destination", "idx_webhook_endpoints_org_active"):
        if index not in webhook_indexes:
            raise SystemExit(f"Missing {index}")
    db.execute("INSERT INTO users (id, email, password_hash) VALUES ('u1', 'test@example.com', 'hash')")
    db.execute("INSERT INTO organizations (id, name, slug) VALUES ('o1', 'Test', 'test')")
    db.execute("INSERT INTO organization_members (organization_id, user_id, role) VALUES ('o1', 'u1', 'owner')")
    db.execute("INSERT INTO users (id, email) VALUES ('u2', 'second@example.com')")
    try:
        db.execute("INSERT INTO organization_members (organization_id, user_id, role) VALUES ('o1', 'u2', 'root')")
    except sqlite3.IntegrityError:
        pass
    else:
        raise SystemExit("Invalid organization role was accepted")

    violations = list(db.execute("PRAGMA foreign_key_check"))
    if violations:
        raise SystemExit(f"Foreign key violations: {violations}")
    print(f"Validated {len(MIGRATIONS)} migrations and {len(required)} required tables.")

if __name__ == "__main__":
    main()
