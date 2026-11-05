import { address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { poseidon, ZERO_32, ZERO_NULLIFIER_PK } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { listTagOf } from "../../src/crypto/keys/list-salt.js";
import {
  readDepositSection,
  relayListSalts,
  type PolicyReadClient,
} from "../../src/proof/policy-proof.js";
import type { RingPolicy } from "../../src/protocol/codec/ring-codecs.js";
import { canopyLevels, QUAD_ARITY } from "../../src/protocol/membership/member-registry.js";
import {
  buildRuleTable,
  encodeRuleTable,
  ListId,
  memberOfAsset,
  policySourceOwners,
  policyTableHash,
} from "../../src/protocol/membership/policy.js";
import { privateListKey } from "../../src/protocol/membership/private-list.js";
import {
  TRACKING_QUAD_HEIGHT,
  TRACKING_SENTINEL,
  trackingRecordHash,
  type TrackingRecord,
} from "../../src/protocol/membership/tracking.js";
import { recordTree } from "../helpers/member-registry.js";
import { ownSources, storageRegistryAccount } from "../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const RECORDS = address("Stor111111111111111111111111111111111111111");
const TRACKING = address("Cura111111111111111111111111111111111111111");
const RING_ID = new Uint8Array(32).fill(0) as Bytes32;
const OWNER = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 9 : 0)) as Bytes32;
const NULLIFIER_PK = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 8 : 0)) as Bytes32;
const SALT = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 7 : 0)) as Bytes32;
const MINT = "So11111111111111111111111111111111111111112";

function zeroNodes(): readonly Bytes32[] {
  const nodes: Bytes32[] = [ZERO_32];
  for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
    const below = nodes[level] as Bytes32;
    nodes.push(poseidon([below, below, below, below]) as Bytes32);
  }
  return nodes;
}

function trackingChain(leaf: TrackingRecord) {
  const zeros = zeroNodes();
  const folded: Bytes32[] = [trackingRecordHash(leaf)];
  for (let level = 0; level < TRACKING_QUAD_HEIGHT; level += 1) {
    const zero = zeros[level] as Bytes32;
    folded.push(poseidon([folded[level] as Bytes32, zero, zero, zero]) as Bytes32);
  }
  const root = folded[TRACKING_QUAD_HEIGHT] as Bytes32;
  const data = new Uint8Array(1610);
  data[0] = 3;
  new DataView(data.buffer).setBigUint64(66, 1n, true);
  data.set(root, 74);
  const pool = (openings: number) => {
    const levels = canopyLevels(openings);
    const height = TRACKING_QUAD_HEIGHT - levels;
    return {
      records: [
        {
          record: leaf,
          path: {
            index: 0,
            siblings: zeros.slice(0, height).map((zero) => [zero, zero, zero]),
          },
        },
      ],
      canopy: Array.from({ length: QUAD_ARITY ** levels }, (_, node) =>
        node === 0 ? (folded[height] as Bytes32) : (zeros[height] as Bytes32),
      ),
      subjects: [0],
    };
  };
  return { data, pool };
}

function saltedRing(list: ListId = ListId.privateBlock): RingPolicy {
  const table = buildRuleTable({
    rules: [
      {
        subject: "outputOwner",
        source: { kind: "lists", present: [], absent: [list] },
        guard: { kind: "always" },
      },
    ],
  });
  const sources = ownSources(table);
  return {
    records: RECORDS,
    tracking: TRACKING,
    hasPolicy: true,
    policyHash: policyTableHash(table, policySourceOwners(sources)),
    sources,
    rules: encodeRuleTable(table),
    generation: 1,
  } as unknown as RingPolicy;
}

function client(leaf: TrackingRecord): PolicyReadClient {
  const chain = trackingChain(leaf);
  const records = recordTree();
  return {
    getAccount: async (account: string) =>
      account === TRACKING
        ? { data: chain.data }
        : storageRegistryAccount([{ hash: records.root, revision: 3n, expiresAt: 0n }]),
    getTrackingRecordPool: async (request: { openings: number }) => chain.pool(request.openings),
    getStorageRecordPool: async (request: { members: readonly Bytes32[]; openings: number }) => ({
      context: { slot: 1n, blockTime: 0n },
      root: { root: records.root, revision: 3n, nextIndex: records.nextIndex },
      ...records.pool(request.members, request.openings),
    }),
  } as unknown as PolicyReadClient;
}

const enrolled: TrackingRecord = {
  ...TRACKING_SENTINEL,
  member: OWNER,
  nullifierPk: NULLIFIER_PK,
};

const read = (leaf: TrackingRecord, listSalts: readonly { owner: Bytes32; salt: Bytes32 }[]) =>
  readDepositSection({
    client: client(leaf),
    ringProgramId: RING,
    ringId: RING_ID,
    config: saltedRing(),
    owner: OWNER,
    nullifierPk: NULLIFIER_PK,
    viewingU: enrolled.viewingU,
    asset: memberOfAsset(MINT as never),
    listSalts,
  });

beforeAll(initializePoseidon);

describe("readDepositSection", () => {
  it("opens an enrolled recipient's salted key on the key holding it", async () => {
    const section = await read({ ...enrolled, listTag: listTagOf(SALT) }, [
      { owner: OWNER, salt: SALT },
    ]);
    expect(section.capacity).toBe(2);
    const [entry] = section.ownerEntries;
    expect(entry?.listSalt).toEqual(SALT);
    expect(entry?.ownSalted).toBe(2);
    expect(section.ownPool?.subjects[2]?.member).toEqual(privateListKey(OWNER, SALT));
    expect(section.ownerEntries).toHaveLength(2);
    expect(section.outputEntries).toHaveLength(2);
  });

  it("refuses an enrolled recipient with no salt and a salt off the row's tag", async () => {
    await expect(read(enrolled, [])).rejects.toMatchObject({ code: "RING_LIST_SALT_MISSING" });
    await expect(read(enrolled, [{ owner: OWNER, salt: SALT }])).rejects.toMatchObject({
      code: "RING_ADDRESS_MISMATCH",
    });
  });

  it("refuses a recipient viewing key off the row, naming the row's revision", async () => {
    const leaf = {
      ...enrolled,
      listTag: listTagOf(SALT),
      viewingU: new Uint8Array(32).fill(0xee) as Bytes32,
      revision: 5n,
    };
    await expect(read(leaf, [{ owner: OWNER, salt: SALT }])).rejects.toMatchObject({
      code: "RING_RECIPIENT_VIEWING_KEY_STALE",
      details: { rowRevision: "5" },
    });
  });

  it("refuses a zero-key recipient holding a row", async () => {
    await expect(
      readDepositSection({
        client: client(enrolled),
        ringProgramId: RING,
        ringId: RING_ID,
        config: saltedRing(),
        owner: OWNER,
        nullifierPk: ZERO_NULLIFIER_PK as Bytes32,
        viewingU: enrolled.viewingU,
        asset: memberOfAsset(MINT as never),
        listSalts: [],
      }),
    ).rejects.toMatchObject({ code: "RING_RECIPIENT_ENROLLED" });
  });
});

describe("relayListSalts", () => {
  const salts = [{ owner: OWNER, salt: SALT }];

  it("sends a salt to a relay on a ring reading a salted list", () => {
    expect(relayListSalts(saltedRing(), salts)).toEqual(salts);
  });

  it("sends none on a ring reading only public lists or no policy", () => {
    expect(relayListSalts(saltedRing(ListId.block), salts)).toEqual([]);
    expect(relayListSalts({ hasPolicy: false } as RingPolicy, salts)).toEqual([]);
  });
});
