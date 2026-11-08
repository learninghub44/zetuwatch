declare module "cloudflare:workers" {
  interface ProvidedEnv {
    DB: D1Database;
    TEST_MIGRATIONS: unknown[];
  }
}
