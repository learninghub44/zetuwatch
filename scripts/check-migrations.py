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
        "maintenance_windows", "status_pages", "status_page_monitors",
    }
    existing = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table'"
    )}
    missing = required - existing
    if missing:
        raise SystemExit(f"Missing tables: {', '.join(sorted(missing))}")

    user_columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
    for column in ("password_hash", "email_verified_at", "updated_at"):
        if column not in user_columns:
            raise SystemExit(f"Missing users.{column}")

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
