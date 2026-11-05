import { address } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedKeypair, SigningKey, type ShieldedAddress } from "@heliuslabs/zolana/keypair";

import { listTagOf } from "../../src/crypto/keys/list-salt.js";
import {
  readDepositSection,
  relayListSalts,
  type PolicyReadClient,
} from "../../src/proof/policy-proof.js";
import type { RingPolicy } from "../../src/protocol/codec/ring-codecs.js";
import {
  buildRuleTable,
  encodeRuleTable,
  ListId,
  memberOfAsset,
  policySourceOwners,
  policyTableHash,
} from "../../src/protocol/membership/policy.js";
import { privateListKey } from "../../src/protocol/membership/private-list.js";
import { CredentialChain } from "../helpers/credential-chain.js";
import { recordTree } from "../helpers/member-registry.js";
import { ownSources, storageRegistryAccount } from "../helpers/ring-accounts.js";

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const RECORDS = address("Stor111111111111111111111111111111111111111");
const RING_ID = new Uint8Array(32).fill(0) as Bytes32;
const SALT = Uint8Array.from({ length: 32 }, (_, at) => (at === 31 ? 7 : 0)) as Bytes32;
const MINT = "So11111111111111111111111111111111111111112";

const recipient = (): ShieldedAddress =>
  ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(5) as Bytes32),
  ).shieldedAddress();
const OWNER = (): Bytes32 => recipient().signingPublicKey.ownerProofInputHash();

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
    hasPolicy: true,
    policyHash: policyTableHash(table, policySourceOwners(sources)),
    sources,
    rules: encodeRuleTable(table),
    generation: 1,
  } as unknown as RingPolicy;
}

/** `listTag` enrolls the recipient under it, `undefined` leaves it absent. */
async function client(listTag: Bytes32 | undefined): Promise<PolicyReadClient> {
  const chain = await CredentialChain.enrolled(RING, []);
  if (listTag !== undefined) chain.enroll(recipient(), listTag);
  const records = recordTree();
  return {
    ...chain.reader(),
    getAccount: async (account: string) =>
      chain.account(account as never) ??
      storageRegistryAccount([{ hash: records.root, revision: 3n, expiresAt: 0n }]),
    getStorageRecordPool: async (request: { members: readonly Bytes32[]; openings: number }) => ({
      context: { slot: 1n, blockTime: 0n },
      root: { root: records.root, revision: 3n, nextIndex: records.nextIndex },
      ...records.pool(request.members, request.openings),
    }),
  } as unknown as PolicyReadClient;
}

const read = async (
  input: Readonly<{
    listTag: Bytes32 | undefined;
    nullifierPk?: Bytes32;
    listSalts: readonly { owner: Bytes32; salt: Bytes32 }[];
  }>,
) =>
  readDepositSection({
    client: await client(input.listTag),
    ringProgramId: RING,
    ringId: RING_ID,
    config: saltedRing(),
    recipient: recipient().signingPublicKey,
    nullifierPk: input.nullifierPk ?? recipient().nullifierPublicKey,
    asset: memberOfAsset(MINT as never),
    listSalts: input.listSalts,
  });

beforeAll(initializePoseidon);

describe("readDepositSection", () => {
  it("opens an enrolled recipient's salted key on the key holding it", async () => {
    const section = await read({
      listTag: listTagOf(SALT),
      listSalts: [{ owner: OWNER(), salt: SALT }],
    });
    expect(section.capacity).toBe(2);
    const [entry] = section.ownerEntries;
    expect(entry?.listSalt).toEqual(SALT);
    expect(entry?.ownSalted).toBe(2);
    expect(section.ownPool?.subjects[2]?.member).toEqual(privateListKey(OWNER(), SALT));
    expect(section.ownerEntries).toHaveLength(2);
    expect(section.outputEntries).toEqual([0, 0]);
    expect(section.credentialOpenings[0]).toMatchObject({ present: true, member: OWNER() });
    expect(section.credentialOpenings[1]).toMatchObject({
      present: false,
      member: new Uint8Array(32),
    });
    expect(section.credentials.read.stateRootIndexes).toEqual([0]);
  });

  it("refuses an enrolled recipient with no salt and a salt off the credential's tag", async () => {
    await expect(
      read({ listTag: new Uint8Array(32) as Bytes32, listSalts: [] }),
    ).rejects.toMatchObject({
      code: "RING_LIST_SALT_MISSING",
    });
    await expect(
      read({ listTag: new Uint8Array(32) as Bytes32, listSalts: [{ owner: OWNER(), salt: SALT }] }),
    ).rejects.toMatchObject({ code: "RING_ADDRESS_MISMATCH" });
  });

  it("refuses an output key other than the credential's", async () => {
    await expect(
      read({
        listTag: listTagOf(SALT),
        nullifierPk: new Uint8Array(32).fill(1) as Bytes32,
        listSalts: [{ owner: OWNER(), salt: SALT }],
      }),
    ).rejects.toMatchObject({ code: "RING_ADDRESS_MISMATCH", details: { field: "nullifierPk" } });
  });

  it("opens an absent zero-key recipient and refuses a zero key to an enrolled one", async () => {
    const zero = ZERO_NULLIFIER_PK as Bytes32;
    const absent = await read({ listTag: undefined, nullifierPk: zero, listSalts: [] });
    expect(absent.credentialOpenings[0]).toMatchObject({ present: false, member: OWNER() });
    expect(absent.credentialOpenings[0]?.lowNext).not.toEqual(new Uint8Array(32));
    await expect(
      read({ listTag: new Uint8Array(32) as Bytes32, nullifierPk: zero, listSalts: [] }),
    ).rejects.toMatchObject({ code: "RING_RECIPIENT_ENROLLED" });
  });
});

describe("relayListSalts", () => {
  const salts = [{ owner: new Uint8Array(32).fill(9) as Bytes32, salt: SALT }];

  it("sends a salt to a relay on a ring reading a salted list", () => {
    expect(relayListSalts(saltedRing(), salts)).toEqual(salts);
  });

  it("sends none on a ring reading only public lists or no policy", () => {
    expect(relayListSalts(saltedRing(ListId.block), salts)).toEqual([]);
    expect(relayListSalts({ hasPolicy: false } as RingPolicy, salts)).toEqual([]);
  });
});
