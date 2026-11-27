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
        "webhook_deliveries", "webhook_delivery_attempts", "probe_agent_replay_nonces",
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
        "secret_ciphertext", "secret_nonce", "secret_last4", "encryption_key_version", "encryption_key_id",
        "is_enabled", "created_by", "deleted_at",
    ):
        if column not in webhook_columns:
            raise SystemExit(f"Missing webhook_endpoints.{column}")
    webhook_indexes = {row[1] for row in db.execute("PRAGMA index_list(webhook_endpoints)")}
    for index in ("idx_webhook_endpoints_org_destination", "idx_webhook_endpoints_org_active", "idx_webhook_endpoints_key_rotation"):
        if index not in webhook_indexes:
            raise SystemExit(f"Missing {index}")

    webhook_delivery_info = {row[1]: row for row in db.execute("PRAGMA table_info(webhook_deliveries)")}
    if webhook_delivery_info.get("next_attempt_at", (None, None, None, 1))[3] != 0:
        raise SystemExit("webhook_deliveries.next_attempt_at must be nullable for terminal rows")
    webhook_delivery_columns = set(webhook_delivery_info)
    for column in (
        "organization_id", "endpoint_id", "incident_id", "event_id", "status",
        "attempt_count", "next_attempt_at", "lease_token", "lease_until",
        "response_status", "last_error_code", "delivered_at",
    ):
        if column not in webhook_delivery_columns:
            raise SystemExit(f"Missing webhook_deliveries.{column}")
    webhook_delivery_indexes = {row[1] for row in db.execute("PRAGMA index_list(webhook_deliveries)")}
    for index in (
        "idx_webhook_deliveries_due", "idx_webhook_deliveries_org_time",
        "idx_webhook_deliveries_endpoint_time",
    ):
        if index not in webhook_delivery_indexes:
            raise SystemExit(f"Missing {index}")

    webhook_attempt_columns = {row[1] for row in db.execute("PRAGMA table_info(webhook_delivery_attempts)")}
    for column in ("delivery_id", "attempt_number", "status", "response_status", "error_code", "started_at", "completed_at"):
        if column not in webhook_attempt_columns:
            raise SystemExit(f"Missing webhook_delivery_attempts.{column}")
    webhook_attempt_indexes = {row[1] for row in db.execute("PRAGMA index_list(webhook_delivery_attempts)")}
    if "idx_webhook_delivery_attempts_delivery_time" not in webhook_attempt_indexes:
        raise SystemExit("Missing idx_webhook_delivery_attempts_delivery_time")
    trigger_names = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type = 'trigger'")}
    for trigger in (
        "webhook_delivery_tenant_guard", "webhook_delivery_identity_immutable",
        "webhook_delivery_attempt_started", "webhook_delivery_attempts_append_only",
        "webhook_delivery_enqueue_after_event", "webhook_delivery_cancel_on_endpoint_disable",
    ):
        if trigger not in trigger_names:
            raise SystemExit(f"Missing {trigger}")
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

    # Exercise the webhook event trigger, tenant guard and attempt-log trigger
    # against the fully migrated SQLite schema.
    db.execute("INSERT INTO monitors (id, organization_id, name, target_url) VALUES ('m1', 'o1', 'Test monitor', 'https://example.com/health')")
    db.execute("INSERT INTO incidents (id, monitor_id, started_at, status, summary) VALUES ('i1', 'm1', '2026-11-25T06:00:00Z', 'investigating', 'Test incident')")
    db.execute("""INSERT INTO webhook_endpoints (
        id, organization_id, name, destination_host, destination_hash,
        destination_ciphertext, destination_nonce, secret_ciphertext, secret_nonce,
        secret_last4, encryption_key_version, is_enabled, created_by
    ) VALUES ('we1', 'o1', 'Receiver', 'hooks.example.com', ?, 'cipher', 'nonce',
        'cipher', 'nonce', '1234', 1, 1, 'u1')""", ("a" * 64,))
    legacy_key_id = db.execute(
        "SELECT encryption_key_id FROM webhook_endpoints WHERE id = 'we1'"
    ).fetchone()[0]
    if legacy_key_id != "v1":
        raise SystemExit(f"Existing webhook rows must default to legacy key id v1: {legacy_key_id}")
    db.execute("UPDATE webhook_endpoints SET encryption_key_id = 'key-v2' WHERE id = 'we1'")
    if db.execute("SELECT encryption_key_id FROM webhook_endpoints WHERE id = 'we1'").fetchone()[0] != "key-v2":
        raise SystemExit("A valid rotated webhook key id was not persisted")
    try:
        db.execute("UPDATE webhook_endpoints SET encryption_key_id = 'bad/key' WHERE id = 'we1'")
    except sqlite3.IntegrityError:
        pass
    else:
        raise SystemExit("Invalid webhook encryption key id was accepted")
    db.execute("UPDATE webhook_endpoints SET encryption_key_id = 'v1' WHERE id = 'we1'")
    db.execute("""INSERT INTO incident_events
        (id, incident_id, event_type, message, created_at)
        VALUES ('ev1', 'i1', 'incident.opened', 'Incident opened', '2026-11-25 06:00:00')""")
    delivery = db.execute("""SELECT organization_id, endpoint_id, incident_id, event_id, status, attempt_count
        FROM webhook_deliveries WHERE event_id = 'ev1'""").fetchone()
    if delivery != ("o1", "we1", "i1", "ev1", "queued", 0):
        raise SystemExit(f"Webhook event fan-out failed: {delivery}")
    db.execute("""UPDATE webhook_deliveries
        SET lease_token = 'migration-check-token-0001',
            lease_until = '2026-11-25T06:02:00.000Z',
            attempt_count = 1,
            updated_at = '2026-11-25T06:01:00.000Z'
        WHERE event_id = 'ev1'""")
    attempt = db.execute("""SELECT attempt_number, status FROM webhook_delivery_attempts
        WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = 'ev1')""").fetchone()
    if attempt != (1, "started"):
        raise SystemExit(f"Webhook attempt log creation failed: {attempt}")
    db.execute("INSERT INTO organizations (id, name, slug) VALUES ('o2', 'Second', 'second')")
    db.execute("""INSERT INTO webhook_endpoints (
        id, organization_id, name, destination_host, destination_hash,
        destination_ciphertext, destination_nonce, secret_ciphertext, secret_nonce,
        secret_last4, encryption_key_version, is_enabled, created_by
    ) VALUES ('we2', 'o2', 'Foreign receiver', 'hooks.example.net', ?, 'cipher', 'nonce',
        'cipher', 'nonce', '5678', 1, 1, 'u2')""", ("b" * 64,))
    try:
        db.execute("""INSERT INTO webhook_deliveries
            (id, organization_id, endpoint_id, incident_id, event_id, status, attempt_count, next_attempt_at)
            VALUES ('bad-delivery', 'o1', 'we2', 'i1', 'ev1', 'queued', 0, '2026-11-25T06:00:00.000Z')""")
    except sqlite3.IntegrityError as error:
        if "WEBHOOK_DELIVERY_TENANT_MISMATCH" not in str(error):
            raise
    else:
        raise SystemExit("Cross-tenant webhook delivery was accepted")
    try:
        db.execute("""UPDATE webhook_delivery_attempts SET error_code = 'TAMPERED'
            WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = 'ev1')""")
    except sqlite3.IntegrityError as error:
        if "WEBHOOK_DELIVERY_ATTEMPTS_IMMUTABLE" not in str(error):
            raise
    else:
        raise SystemExit("Started webhook attempt row accepted an in-place mutation")
    db.execute("""UPDATE webhook_endpoints
        SET is_enabled = 0, deleted_at = '2026-11-25T06:02:00.000Z'
        WHERE id = 'we1'""")
    cancelled = db.execute("""SELECT status, next_attempt_at, lease_token
        FROM webhook_deliveries WHERE event_id = 'ev1'""").fetchone()
    if cancelled != ("cancelled", None, None):
        raise SystemExit(f"Endpoint disable did not cancel delivery: {cancelled}")
    abandoned = db.execute("""SELECT status, error_code FROM webhook_delivery_attempts
        WHERE delivery_id = (SELECT id FROM webhook_deliveries WHERE event_id = 'ev1')""").fetchone()
    if abandoned != ("abandoned", "ENDPOINT_DISABLED"):
        raise SystemExit(f"Endpoint disable did not close active attempt: {abandoned}")

    replay_indexes = {row[1] for row in db.execute("PRAGMA index_list(probe_agent_replay_nonces)")}
    if "idx_probe_agent_replay_nonces_expiry" not in replay_indexes:
        raise SystemExit("Missing idx_probe_agent_replay_nonces_expiry")

    replay_nonce = "a" * 64
    replay_now = "2026-11-27T10:00:00.000Z"
    replay_future = "2026-11-27T10:05:00.000Z"
    db.execute(
        "INSERT INTO probe_agent_replay_nonces (nonce_hash, expires_at, created_at) VALUES (?, ?, ?)",
        (replay_nonce, replay_future, replay_now),
    )
    db.execute(
        "INSERT OR IGNORE INTO probe_agent_replay_nonces (nonce_hash, expires_at, created_at) VALUES (?, ?, ?)",
        (replay_nonce, replay_future, replay_now),
    )
    replay_count = db.execute(
        "SELECT COUNT(*) FROM probe_agent_replay_nonces WHERE nonce_hash = ?", (replay_nonce,)
    ).fetchone()[0]
    if replay_count != 1:
        raise SystemExit("Probe-agent replay nonce uniqueness is not enforced")
    db.execute(
        "INSERT INTO probe_agent_replay_nonces (nonce_hash, expires_at, created_at) VALUES (?, ?, ?)",
        ("b" * 64, "2026-11-27T09:59:00.000Z", "2026-11-27T09:58:00.000Z"),
    )
    db.execute("DELETE FROM probe_agent_replay_nonces WHERE expires_at <= ?", (replay_now,))
    expired_count = db.execute(
        "SELECT COUNT(*) FROM probe_agent_replay_nonces WHERE nonce_hash = ?", ("b" * 64,)
    ).fetchone()[0]
    if expired_count != 0:
        raise SystemExit("Expired probe-agent replay nonces were not pruned")
    try:
        db.execute(
            "INSERT INTO probe_agent_replay_nonces (nonce_hash, expires_at, created_at) VALUES (?, ?, ?)",
            ("not-a-hash", replay_future, replay_now),
        )
        raise SystemExit("Probe-agent replay nonce hash constraint was not enforced")
    except sqlite3.IntegrityError:
        pass

    violations = list(db.execute("PRAGMA foreign_key_check"))
    if violations:
        raise SystemExit(f"Foreign key violations: {violations}")
    print(f"Validated {len(MIGRATIONS)} migrations and {len(required)} required tables.")

if __name__ == "__main__":
    main()
