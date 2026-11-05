import { address, generateKeyPairSigner, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

import { Reader, SYSTEM_PROGRAM, addressBytes } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { hexToBytes } from "@noble/hashes/utils.js";

import { listTagOf } from "../../../src/crypto/keys/list-salt.js";
import {
  decodeOwnerGrant,
  ownerGrantInstruction,
} from "../../../src/operations/management/enrollment.js";
import { ownerGrantPda, STORAGE_PROGRAM_ID } from "../../../src/protocol/pda/index.js";

const RING = address("Cura111111111111111111111111111111111111111");
const OTHER_RING = address("Stor111111111111111111111111111111111111111");
const READER = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");

describe("owner grant", () => {
  it("decodes an owner grant, only one means active", () => {
    const data = Uint8Array.of(5, 1);
    expect(decodeOwnerGrant(data).active).toBe(true);
    data[1] = 0;
    expect(decodeOwnerGrant(data).active).toBe(false);
  });

  it("refuses an account off its discriminator or size", () => {
    expect(() => decodeOwnerGrant(Uint8Array.of(4, 1))).toThrow("RING_OWNER_GRANT_INVALID");
    expect(() => decodeOwnerGrant(Uint8Array.of(5, 1, 0))).toThrow("RING_OWNER_GRANT_INVALID");
  });

  it("writes tag 8 with the ring program, the reader and the flag under the ring's grant address", async () => {
    const owner = await generateKeyPairSigner();
    const built = await ownerGrantInstruction({
      payer: owner,
      owner,
      ringProgramId: RING,
      reader: READER,
      active: true,
    });
    const data = new Reader(new Uint8Array(built.data ?? []));
    expect(data.u8("tag")).toBe(8);
    expect(data.bytes(32, "ringProgramId")).toEqual(addressBytes(RING, "ring"));
    const reader = data.bytes(34, "reader");
    expect(data.u8("active")).toBe(1);
    data.done();
    const [grant] = await ownerGrantPda(RING, owner.address, reader);
    expect(built.programAddress).toBe(STORAGE_PROGRAM_ID);
    expect(built.accounts?.map((account) => account.address)).toEqual([
      owner.address,
      owner.address,
      grant,
      SYSTEM_PROGRAM,
    ]);
  });

  it("derives another grant address for another ring, a grant reads in one namespace", async () => {
    const owner = await generateKeyPairSigner();
    const grant = async (ringProgramId: Address) =>
      (
        await ownerGrantInstruction({
          payer: owner,
          owner,
          ringProgramId,
          reader: READER,
          active: true,
        })
      ).accounts?.[2]?.address;
    expect(await grant(RING)).not.toBe(await grant(OTHER_RING));
  });
});
