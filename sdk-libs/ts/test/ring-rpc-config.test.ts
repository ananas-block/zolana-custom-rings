import { describe, expect, it, vi } from "vitest";

import { RingRpc } from "../src/ring/rpc.js";

// A browser's `fetch` throws "Illegal invocation" unless called on the global,
// which a stored method reference is not. The stub enforces the same rule.
function strictFetch() {
  const calls: unknown[] = [];
  const fetch: typeof globalThis.fetch = function (
    this: unknown,
    ...args: Parameters<typeof globalThis.fetch>
  ) {
    if (this !== globalThis && this !== undefined) throw new TypeError("Illegal invocation");
    calls.push(args[0]);
    return Promise.resolve(
      new Response(
        JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          result: { mode: "local", servicePubkey: "11111111111111111111111111111111" },
        }),
        {
          headers: { "content-type": "application/json" },
        },
      ),
    );
  };
  return { fetch, calls };
}

describe("ring rpc fetch binding", () => {
  it("calls the global fetch on the global", async () => {
    const { fetch, calls } = strictFetch();
    vi.stubGlobal("fetch", fetch);
    try {
      await new RingRpc("http://ring.example", { allowInsecureHttp: true }).health();
      expect(calls).toHaveLength(1);
    } finally {
      vi.unstubAllGlobals();
    }
  });
});

const create = (url: string, fetch: typeof globalThis.fetch, apiKey?: string) =>
  new RingRpc(url, { fetch, ...(apiKey === undefined ? {} : { apiKey }) });
const code = "RING_RPC_CONFIG";

describe("RingRpc gateway configuration", () => {
  it.each([
    { query: "", key: "" },
    { query: "", key: "key\nvalue" },
    { query: "", key: "k".repeat(4097) },
    { query: "?api-key=one", key: "two" },
    { query: "?api-key=one&api%2Dkey=two", key: undefined },
    { query: "?api-key=", key: undefined },
    { query: "?api-key=key%00value", key: undefined },
  ])("rejects invalid or ambiguous key sources ($query)", ({ query, key }) => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create(`https://gateway.example${query}`, fetch, key)).toThrow(
      expect.objectContaining({ code, details: { field: "apiKey" } }),
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it.each(["\uD800", "\uDC00", "secret\uD800key", "\uDC00\uD800"])(
    "rejects an unpaired surrogate before any request (%j)",
    (key) => {
      const fetch = vi.fn<typeof globalThis.fetch>();
      expect(() => create("https://gateway.example", fetch, key)).toThrow(
        expect.objectContaining({ code, details: { field: "apiKey" } }),
      );
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("accepts well-formed Unicode without rejecting surrogate pairs", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create("https://gateway.example", fetch, "key-🔑-é")).not.toThrow();
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("RingRpc gateway URL", () => {
  it.each(["%ED%A0%80", "%FF", "%", "%C0%AF", "", "key%00value"])(
    "rejects a malformed encoded URL key before any request (%s)",
    (key) => {
      const fetch = vi.fn<typeof globalThis.fetch>();
      expect(() => create(`https://gateway.example?api-key=${key}`, fetch)).toThrow(
        expect.objectContaining({ code, details: { field: "apiKey" } }),
      );
      expect(fetch).not.toHaveBeenCalled();
    },
  );

  it("refuses duplicate keys including encoded parameter names", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    expect(() => create("https://gateway.example?api-key=one&api%2Dkey=two", fetch)).toThrow(
      expect.objectContaining({ code, details: { field: "apiKey" } }),
    );
    expect(fetch).not.toHaveBeenCalled();
  });
});
