import { readFileSync } from "node:fs";

import { getBase58Decoder } from "@solana/kit";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { generateKeyPairSigner } from "@solana/kit";
import type { Address } from "@solana/kit";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { X25519Keypair } from "@heliuslabs/zolana/keypair";
import { ZERO_32, addressBytes } from "@heliuslabs/zolana/internal";

import {
  authorizationAddressHash,
  checkedEnrollAddressInstruction,
  decodeAddressAuthorization,
  enrollAddressInstruction,
  type EnrollAddress,
  type EnrollmentReadClient,
} from "../../../src/operations/management/enroll-address.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import { escrowKeyHash } from "../../../src/protocol/membership/member-opening.js";
import type { StorageOpeningsRequest } from "../../../src/rpc/ports.js";
import { recordTree, type FixtureRecord } from "../../helpers/member-registry.js";
import { storageRegistryAccount } from "../../helpers/ring-accounts.js";
import {
  decodeStorageWrites,
  encodeStorageWrites,
} from "../../../src/protocol/codec/storage-writes.js";
import {
  addressRecordHash,
  queueEntryHash,
} from "../../../src/protocol/membership/member-opening.js";
import { addressAuthorizationPda } from "../../../src/protocol/pda/index.js";

const vector = JSON.parse(
  readFileSync(
    new URL("../../../../../test-vectors/registry/enroll_address.json", import.meta.url),
    "utf8",
  ),
) as Record<string, string | number>;
const hex = (name: string): Bytes32 => hexToBytes(vector[name] as string) as Bytes32;
const base58 = getBase58Decoder();
const address = (name: string): Address => base58.decode(hex(name)) as Address;

describe("enroll_address vector", () => {
  beforeAll(initializePoseidon);

  it("decodes the account and derives its address hash", () => {
    const authorization = decodeAddressAuthorization(hex("account"));
    expect(authorization.bump).toBe(vector["bump"]);
    expect(authorization.registry).toBe(address("registry"));
    expect(authorization.owner).toBe(address("owner"));
    expect(authorization.addressRevision).toBe(BigInt(vector["address_revision"] as number));
    expect(bytesToHex(authorizationAddressHash(authorization))).toBe(vector["address_hash"]);
    expect(
      bytesToHex(
        addressRecordHash({
          ringId: hex("ring_id"),
          member: hex("member"),
          nullifierPk: hex("nullifier_pk"),
          viewingU: hex("viewing_u"),
          addressRevision: 1n,
        }),
      ),
    ).toBe(vector["address_hash"]);
  });

  it("names the authorization under the registry and the owner", async () => {
    const [authorization] = await addressAuthorizationPda(address("registry"), address("owner"));
    expect(authorization).toBe(address("authorization"));
  });

  it("writes tag 5 then the nullifier key then the viewing key", async () => {
    const owner = await generateKeyPairSigner();
    const instruction = await enrollAddressInstruction({
      payer: owner,
      owner,
      registry: address("registry"),
      nullifierPk: hex("nullifier_pk"),
      viewingU: hex("viewing_u"),
    });
    expect(instruction.data?.[0]).toBe(5);
    expect(bytesToHex(new Uint8Array(instruction.data ?? []).subarray(1))).toBe(
      vector["enroll_data"],
    );
  });

  it("reads the address write and chains its entry", () => {
    const write = decodeStorageWrites(hex("address_write"));
    expect(write).toEqual([{ kind: "address", owner: address("owner"), addressRevision: 1n }]);
    expect(bytesToHex(encodeStorageWrites(write))).toBe(vector["address_write"]);
    expect(
      bytesToHex(
        queueEntryHash({
          member: hex("member"),
          mask: 0n,
          value: 0n,
          escrowKey: ZERO_32,
          addressHash: hex("address_hash"),
        }),
      ),
    ).toBe(vector["entry_hash"]);
  });
});

describe("checkedEnrollAddressInstruction", () => {
  beforeAll(initializePoseidon);

  const registry = address("registry");
  const held = new Uint8Array(32).fill(7) as Bytes32;
  const other = new Uint8Array(32).fill(8) as Bytes32;
  const viewingU = new Uint8Array(32).fill(3) as Bytes32;

  function chain(records: readonly FixtureRecord[]): EnrollmentReadClient {
    const tree = recordTree(records);
    const account = storageRegistryAccount([{ hash: tree.root, revision: 1n, expiresAt: 0n }]);
    return {
      getAccount: async (key: Address) => (key === registry ? account : undefined),
      getStorageMemberOpenings: async (request: StorageOpeningsRequest) => ({
        context: { slot: 1n, blockTime: 0n },
        root: { root: tree.root, revision: 1n, nextIndex: tree.nextIndex },
        openings: request.members.map((member: Bytes32) => tree.opening(member)),
      }),
    } as unknown as EnrollmentReadClient;
  }

  async function enrollment(nullifierPk: Bytes32): Promise<EnrollAddress> {
    const owner = await generateKeyPairSigner();
    return { payer: owner, owner, registry, nullifierPk, viewingU };
  }

  const memberOf = (input: EnrollAddress): Bytes32 =>
    memberOfTag(addressBytes((input.owner as { address: Address }).address, "owner"));

  it("builds the same instruction when no record exists", async () => {
    const input = await enrollment(held);
    const checked = await checkedEnrollAddressInstruction(input, chain([]));
    expect(checked).toEqual(await enrollAddressInstruction(input));
  });

  it("builds for a record that holds no key yet and for the key an address already holds", async () => {
    const input = await enrollment(held);
    const member = memberOf(input);
    await checkedEnrollAddressInstruction(input, chain([{ member, lists: 1n }]));
    await checkedEnrollAddressInstruction(
      input,
      chain([
        {
          member,
          lists: 0n,
          address: { ringId: hex("ring_id"), nullifierPk: held, viewingU, addressRevision: 1n },
        },
      ]),
    );
  });

  it("refuses a key other than the address holds before the owner signs", async () => {
    const input = await enrollment(other);
    await expect(
      checkedEnrollAddressInstruction(
        input,
        chain([
          {
            member: memberOf(input),
            lists: 0n,
            address: { ringId: hex("ring_id"), nullifierPk: held, viewingU, addressRevision: 1n },
          },
        ]),
      ),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
  });

  it("reads the escrow against the sealed key the record binds", async () => {
    const ciphertext = new Uint8Array(32).fill(9) as Bytes32;
    const escrowed = (input: EnrollAddress, withSealed: boolean): FixtureRecord => ({
      member: memberOf(input),
      lists: 0n,
      escrowKey: escrowKeyHash({ nullifierPk: held, ciphertext }),
      ...(withSealed
        ? {
            sealed: {
              owner: address("owner"),
              nullifierPk: held,
              ephemeralPublicKey: X25519Keypair.generate().publicKey(),
              ciphertext,
            },
          }
        : {}),
    });
    const agrees = await enrollment(held);
    await checkedEnrollAddressInstruction(agrees, chain([escrowed(agrees, true)]));
    const differs = await enrollment(other);
    await expect(
      checkedEnrollAddressInstruction(differs, chain([escrowed(differs, true)])),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
    const withheld = await enrollment(held);
    await expect(
      checkedEnrollAddressInstruction(withheld, chain([escrowed(withheld, false)])),
    ).rejects.toMatchObject({ code: "RING_ENROLLMENT_KEY_MISMATCH" });
  });
});
