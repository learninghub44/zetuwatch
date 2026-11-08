import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(new URL("./database/migrations", import.meta.url).pathname);

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // Migrations are read by Vitest's Node process and passed into the
          // isolated workerd runtime as a test-only binding.
          bindings: { TEST_MIGRATIONS: migrations }
        }
      })
    ],
    test: {
      include: ["**/*.test.ts"],
      setupFiles: ["./tests/apply-migrations.ts"]
    }
  };
});
