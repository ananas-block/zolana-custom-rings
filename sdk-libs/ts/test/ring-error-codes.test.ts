import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { RING_KEY_ERROR_RUST_VARIANT } from "../src/keypair/error.js";
import { RING_ERROR_CODES } from "../src/ring/error.js";

describe("ring error codes", () => {
  it("pins the public codes and their order", () => {
    expect(new Set(RING_ERROR_CODES).size).toBe(RING_ERROR_CODES.length);
    expect(RING_ERROR_CODES).toMatchSnapshot();
  });
});

describe("RING_KEY_ERROR_RUST_VARIANT", () => {
  const sources = new Map([
    ["RingKeyError", "../../keys/src/error.rs"],
    ["StreamError", "../../../program-libs/interface/src/stream.rs"],
    ["AuditError", "../../client/src/error.rs"],
  ]);
  const variants = (name: string): readonly string[] => {
    const file = sources.get(name);
    if (file === undefined) return [];
    const body = readFileSync(new URL(file, import.meta.url), "utf8")
      .split(`pub enum ${name} {`)[1]
      ?.split(/^\}/mu)[0];
    return [...(body ?? "").matchAll(/^ {4}([A-Z][A-Za-z0-9]*)\b/gmu)].map(
      ([, variant]) => variant ?? "",
    );
  };

  it("names a variant of the Rust enum each code mirrors", () => {
    for (const [code, named] of Object.entries(RING_KEY_ERROR_RUST_VARIANT)) {
      if (named === null) continue;
      const [name, variant] = named.includes("::") ? named.split("::") : ["RingKeyError", named];
      expect(variants(name ?? ""), code).toContain(variant);
    }
  });
});
