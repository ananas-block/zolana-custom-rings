import { Reader, Writer } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";

import { RingError } from "../error.js";
import {
  MINT_POLICY_LEN,
  mintPolicyFromBytes,
  mintPolicyWrite,
  type MintPolicy,
} from "../membership/mint-policy.js";
import { memberOfIdentity, type Member } from "../membership/policy.js";

/** Rust `RecordWriteData::SIZE`. */
const RECORD_LENGTH = 145;

/** Rust `RecordWriteData`. */
export interface StorageWrite {
  readonly member: Member;
  readonly mask: bigint;
  readonly value: bigint;
  /** Absent keeps the record's mint settings. */
  readonly mintPolicy?: MintPolicy;
}

export function encodeStorageWrites(writes: readonly StorageWrite[]): Uint8Array {
  const writer = new Writer();
  for (const write of writes)
    writer
      .bytes(write.member, 32, "member")
      .u64(write.mask, "mask")
      .u64(write.value, "value")
      .bytes(mintPolicyWrite(write.mintPolicy));
  return writer.finish();
}

/** Refuses a partial write, a mint settings tag past 1 or nonzero settings under tag 0. */
export function decodeStorageWrites(data: Uint8Array): readonly StorageWrite[] {
  if (data.length % RECORD_LENGTH !== 0) throw invalid(data.length);
  const writes: StorageWrite[] = [];
  for (let offset = 0; offset < data.length; offset += RECORD_LENGTH) {
    try {
      writes.push(recordWrite(new Reader(data.subarray(offset, offset + RECORD_LENGTH))));
    } catch (cause) {
      throw invalid(offset, cause);
    }
  }
  return Object.freeze(writes);
}

function recordWrite(reader: Reader): StorageWrite {
  const member = memberOfIdentity(reader.bytes(32, "member") as Bytes32);
  const mask = reader.u64("mask");
  const value = reader.u64("value");
  const tag = reader.u8("mintPolicy.tag");
  const policy = reader.bytes(MINT_POLICY_LEN, "mintPolicy");
  reader.done();
  if (tag === 1)
    return Object.freeze({ member, mask, value, mintPolicy: mintPolicyFromBytes(policy) });
  if (tag !== 0 || !policy.every((byte) => byte === 0))
    throw new RingError("RING_STORAGE_WRITE_INVALID", { details: { field: "mintPolicy" } });
  return Object.freeze({ member, mask, value });
}

function invalid(offset: number, cause?: unknown): RingError {
  return new RingError("RING_STORAGE_WRITE_INVALID", {
    details: { offset },
    ...(cause === undefined ? {} : { cause }),
  });
}
