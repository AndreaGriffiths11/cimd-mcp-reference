import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc" },
      miniflare: {
        bindings: {
          ISSUER: "http://localhost:8787",
          DEV_ALLOW_LOOPBACK_CLIENT_IDS: "true",
          ENABLE_DEPRECATED_DCR: "false",
          ALLOWED_ORIGINS: "",
          CIMD_ALLOWED_HOSTS: "",
        },
      },
    }),
  ],
  test: {
    include: ["test/**/*.test.ts"],
  },
});
