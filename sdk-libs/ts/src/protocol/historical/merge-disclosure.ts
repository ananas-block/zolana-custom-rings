import { Reader, encodeBase58, bytesToBigInt } from "@heliuslabs/zolana/internal";
import { InterfaceError } from "@heliuslabs/zolana/interface";
import type { Address, Bytes16, Bytes32 } from "@heliuslabs/zolana/interface";
import { symmetricApply, X25519PublicKey, type X25519Keypair } from "@heliuslabs/zolana/keypair";

import { auditSharedSecret, openMergeDisclosureFields } from "../../crypto/audit/audit.js";
import {
  readRingMergeDisclosure,
  type RingMergeDisclosure,
} from "../../crypto/audit/merge-disclosure.js";
import { RingError } from "../error.js";
import { RingInstructionTag } from "../transaction/instruction-tag.js";
import { MERGE_WIDTHS, packedChunks } from "./layout.js";

const MERGE_DISCLOSURE_INFO = new TextEncoder().encode("CRING/mrg1");
/** Owner key, nullifier pk, mint, amount and output blinding ahead of the input commitments. */
const MERGE_DISCLOSURE_HEADER_LENGTH = 32 + 32 + 32 + 8 + 32;
/** `tag ‖ own_revision ‖ ring_data_hash`. */
const MERGE_DISCLOSURE_OFFSET = 1 + 8 + 32;

export interface HistoricalMergeOpening {
  readonly ownerKey: Address;
  readonly nullifierPublicKey: Bytes32;
  readonly mint: Address;
  readonly amount: bigint;
  readonly outputBlinding: Bytes32;
  /** One per circuit slot, zero for padding. */
  readonly inputCommitments: readonly Bytes32[];
}

export function historicalMergeFieldCount(width: number): number {
  return packedChunks(MERGE_DISCLOSURE_HEADER_LENGTH + 32 * width);
}

/** `instruction` leads with the tag, the SPP merge body behind the disclosure stays unread. */
export function readHistoricalMergeDisclosure(instruction: Uint8Array): RingMergeDisclosure {
  if (instruction[0] !== RingInstructionTag.historicalMerge) throw invalid("merge tag");
  try {
    return readRingMergeDisclosure(new Reader(instruction.subarray(MERGE_DISCLOSURE_OFFSET)));
  } catch (cause) {
    if (cause instanceof InterfaceError)
      throw new RingError("RING_AUDIT_MESSAGE", { details: { reason: "merge frame" }, cause });
    throw cause;
  }
}

export function openHistoricalMergeDisclosure(
  auditor: X25519Keypair,
  disclosure: Pick<RingMergeDisclosure, "ephemeralPublicKey" | "ciphertext" | "fields">,
  salt: Bytes16,
): HistoricalMergeOpening {
  const width = MERGE_WIDTHS.find(
    (count) => historicalMergeFieldCount(count) === disclosure.fields.length,
  );
  if (width === undefined) throw invalid("disclosure width");
  const ephemeral = X25519PublicKey.fromBytes(disclosure.ephemeralPublicKey);
  const dh = auditor.ecdh(ephemeral);
  const shared = auditSharedSecret(dh, ephemeral, auditor.publicKey());
  const key = symmetricApply(shared, MERGE_DISCLOSURE_INFO, disclosure.ciphertext) as Bytes32;
  let plaintext: Uint8Array | undefined;
  try {
    const opened = openMergeDisclosureFields(key, salt, disclosure.fields);
    plaintext = opened;
    const length = MERGE_DISCLOSURE_HEADER_LENGTH + 32 * width;
    if (opened.subarray(length).some((byte) => byte !== 0)) throw invalid("disclosure padding");
    const at = (offset: number, size = 32): Uint8Array => opened.slice(offset, offset + size);
    return Object.freeze({
      ownerKey: encodeBase58(at(0)),
      nullifierPublicKey: at(32) as Bytes32,
      mint: encodeBase58(at(64)),
      amount: bytesToBigInt(at(96, 8)),
      outputBlinding: at(104) as Bytes32,
      inputCommitments: Object.freeze(
        Array.from(
          { length: width },
          (_, index) => at(MERGE_DISCLOSURE_HEADER_LENGTH + 32 * index) as Bytes32,
        ),
      ),
    });
  } finally {
    dh.fill(0);
    shared.fill(0);
    key.fill(0);
    plaintext?.fill(0);
  }
}

function invalid(reason: string): RingError {
  return new RingError("RING_AUDIT_MESSAGE", { details: { reason } });
}
