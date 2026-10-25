import { bigIntBytes, bytesToBigInt } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { RingError } from "../error.js";

/** Per-mint settings stored in the ring's authenticated asset record. */
export interface MintPolicy {
  readonly threshold: bigint;
  readonly cap: bigint;
  readonly cosignAbove: bigint;
  readonly withdrawalThreshold: bigint;
}

export const EMPTY_MINT_POLICY: MintPolicy = Object.freeze({
  threshold: 0n,
  cap: 0n,
  cosignAbove: 0n,
  withdrawalThreshold: 0n,
});

/** Three u64 amounts packed in the same order as Rust `MintPolicy::field`. */
export function mintPolicyField(policy: MintPolicy): Bytes32 {
  if (
    typeof policy.withdrawalThreshold !== "bigint" ||
    policy.withdrawalThreshold < 0n ||
    policy.withdrawalThreshold > 0xffff_ffff_ffff_ffffn
  )
    throw new RingError("RING_MEMBER_REGISTRY_INVALID");
  let packed = 0n;
  for (const amount of [policy.threshold, policy.cap, policy.cosignAbove]) {
    if (typeof amount !== "bigint" || amount < 0n || amount > 0xffff_ffff_ffff_ffffn)
      throw new RingError("RING_MEMBER_REGISTRY_INVALID", {
        details: { reason: "MintPolicyRange" },
      });
    packed = (packed << 64n) | amount;
  }
  return bigIntBytes(packed) as Bytes32;
}

/** Bit 192 marks a replacement, including clearing all four settings. */
export function mintPolicyWriteField(policy: MintPolicy | undefined): Bytes32 {
  return bigIntBytes(
    policy === undefined ? 0n : (1n << 192n) | bytesToBigInt(mintPolicyField(policy)),
  ) as Bytes32;
}
