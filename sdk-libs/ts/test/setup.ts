import { beforeAll } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";

beforeAll(async () => {
  await initializePoseidon();
});
