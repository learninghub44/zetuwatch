import { applyD1Migrations } from "cloudflare:test";
import { env } from "cloudflare:workers";

// Each test file gets an isolated D1 database. This is safe to run from a
// setup file because applyD1Migrations skips migration versions already seen.
await applyD1Migrations(
  env.DB,
  env.TEST_MIGRATIONS as Parameters<typeof applyD1Migrations>[1]
);
