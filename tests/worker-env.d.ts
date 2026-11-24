declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    TEST_MIGRATIONS: import("cloudflare:test").D1Migration[];
    WEBHOOK_ENCRYPTION_KEY: string;
  }

  interface GlobalProps {
    mainModule: typeof import("../apps/api/src/index");
  }
}
