import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { run } from "../src/conformance.ts";

const VECTORS = fileURLToPath(new URL("../../../vectors", import.meta.url));

test("every shared vector passes", () => {
  const { passed, failed } = run(VECTORS);
  assert.ok(passed >= 70, `only ${passed} checks ran`);
  assert.deepEqual(failed, []);
});
