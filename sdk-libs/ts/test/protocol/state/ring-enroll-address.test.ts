import { readFileSync } from "node:fs";

import { getBase58Decoder } from "@solana/kit";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "@heliuslabs/zolana";
import { generateKeyPairSigner } from "@solana/kit";
import type { Address } from "@solana/kit";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ZERO_32 } from "@heliuslabs/zolana/internal";

import {
  authorizationAddressHash,
  decodeAddressAuthorization,
  enrollAddressInstruction,
} from "../../../src/operations/management/enroll-address.js";
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
