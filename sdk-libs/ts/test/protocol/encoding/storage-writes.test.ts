import { createKeyPairSignerFromPrivateKeyBytes } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vector from "../../../../../test-vectors/registry/storage_writes.json" with { type: "json" };
import type { Bytes33 } from "@heliuslabs/zolana/interface";
import { addressBytes } from "@heliuslabs/zolana/internal";
import {
  decodeStorageWrites,
  encodeStorageWrites,
  type StorageWrite,
} from "../../../src/protocol/codec/storage-writes.js";
import {
  P256ReaderKey,
  readerKeyMember,
} from "../../../src/operations/management/reader-access.js";
import {
  ListId,
  memberOfTag,
  recordBit,
  walletGrantMember,
} from "../../../src/protocol/membership/policy.js";

/** The vector's record writes, each behind the one-byte kind `RecordWriteData` no longer carries. */
function recordWrites(): string {
  const length = 2 * (1 + 145);
  const rows = [vector.writes.slice(0, length), vector.writes.slice(length, 2 * length)];
  rows.forEach((row) => expect(row.slice(0, 2)).toBe("00"));
  return rows.map((row) => row.slice(2)).join("");
}

describe("RecordWriteData", () => {
  it("writes and reads a wallet update byte for byte as the Rust vector", async () => {
    const wallet = await createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(7));
    const identity = memberOfTag(addressBytes(wallet.address));
    const passkey = P256ReaderKey.fromBytes(
      Uint8Array.from(
        Buffer.from("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "hex"),
      ) as Bytes33,
    );
    const viewing = recordBit(ListId.ringViewing);
    const reader = recordBit(ListId.reader);
    const writes: readonly StorageWrite[] = [
      {
        member: identity,
        mask: viewing,
        value: viewing,
        mintPolicy: {
          threshold: 1n,
          cap: 2n,
          cosignAbove: 3n,
          withdrawalThreshold: 4n,
          limits: {
            senderCap: 5n,
            senderWindowSlots: 6n,
            volumeCap: 7n,
            volumeWindowSlots: 8n,
            depositCap: 9n,
            depositWindowSlots: 10n,
            withdrawalCap: 11n,
            withdrawalWindowSlots: 12n,
          },
        },
      },
      {
        member: walletGrantMember(identity, readerKeyMember(passkey)),
        mask: reader,
        value: reader,
      },
    ];
    const expected = recordWrites();
    expect(Buffer.from(encodeStorageWrites(writes)).toString("hex")).toBe(expected);
    expect(decodeStorageWrites(Uint8Array.from(Buffer.from(expected, "hex")))).toEqual(writes);
    expect(() => decodeStorageWrites(Uint8Array.of(2))).toThrow(
      expect.objectContaining({ code: "RING_STORAGE_WRITE_INVALID" }),
    );
  });
});
