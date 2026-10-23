import { fileURLToPath } from "node:url";

import { defineConfig } from "vitest/config";

const core = fileURLToPath(new URL("../../zolana/sdk-libs/ts/src/", import.meta.url));

export default defineConfig({
  resolve: {
    // Tests and core test helpers share one instance of the core source.
    alias: [
      { find: /^@heliuslabs\/zolana$/u, replacement: `${core}index.ts` },
      {
        find: /^@heliuslabs\/zolana\/(addresses|instructions|internal)$/u,
        replacement: `${core}$1.ts`,
      },
      {
        find: /^@heliuslabs\/zolana\/(client|interface|keypair|transaction|wallet)$/u,
        replacement: `${core}$1/index.ts`,
      },
    ],
  },
  test: {
    environment: "node",
    include: ["test/**/*.test.ts"],
    setupFiles: ["./test/setup.ts"],
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
});
