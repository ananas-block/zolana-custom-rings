/** The withdrawal exemption, the waiver of the co-signer the withdrawal class alone demands, Rust `pipeline::withdrawals`. */
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import { equalBytes } from "@heliuslabs/zolana/internal";

import type { RingPolicy } from "../protocol/codec/ring-codecs.js";
import type { MemberRecord, RecordPool } from "../protocol/membership/member-registry.js";
import { coSignRequirement, type CoSignDemand } from "./cosign.js";

/** `true` when waiving the withdrawals leaves no co-signer demand, approval and the other classes stay. */
export function waivesCoSigner(
  input: Readonly<{
    ringProgramId: Address;
    config: RingPolicy;
    demand: CoSignDemand;
    approvalRequired: boolean;
  }>,
): boolean {
  const required = (withdrawalExempt: boolean) => coSignRequirement({ ...input, withdrawalExempt });
  return (
    input.demand.withdrawals.length > 0 &&
    required(false) !== undefined &&
    required(true) === undefined
  );
}

/** `true` when each public slot's gross lies within its asset record's threshold, the bound the proof asserts. */
export function thresholdsCover(
  pool: RecordPool,
  assets: readonly Bytes32[],
  gross: readonly bigint[],
): boolean {
  return assets.every((asset, slot) => {
    const total = gross[slot] ?? 0n;
    if (total === 0n) return true;
    const record = poolRecord(pool, asset);
    return record !== undefined && record.mintPolicy.withdrawalThreshold >= total;
  });
}

/** The member's record, `undefined` for an absent member or one outside the pool. */
export function poolRecord(pool: RecordPool, member: Bytes32): MemberRecord | undefined {
  const subject = pool.subjects.find((entry) => equalBytes(entry.member, member));
  const record = subject === undefined ? undefined : pool.records[subject.recordIndex];
  return record !== undefined && equalBytes(record.member, member) ? record : undefined;
}
