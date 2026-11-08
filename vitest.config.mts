import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => {
  const migrations = await readD1Migrations(new URL("./database/migrations", import.meta.url).pathname);

  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.toml" },
        miniflare: {
          // These are test-only string bindings. The auth integration test
          // stubs fetch, so no request can reach Resend or send real email.
          bindings: {
            APP_ENV: "test",
            PUBLIC_APP_URL: "https://app.zetuwatch.test",
            RESEND_API_KEY: "test-only-resend-key",
            EMAIL_FROM: "ZetuWatch Tests <noreply@example.test>",
            TEST_MIGRATIONS: migrations
          }
        }
      })
    ],
    test: {
      include: ["**/*.test.ts"],
      setupFiles: ["./tests/apply-migrations.ts"]
    }
  };
});
