/** One co-sign rule for the program and the SDKs, Rust `instructions::cosign`. */
import type { Address } from "@solana/kit";

import type { ChainReader } from "@heliuslabs/zolana/client";
import type { RequestContext } from "@heliuslabs/zolana/interface";

import {
  RING_COSIGN_APPROVE_OUTFLOW,
  RING_COSIGN_APPROVE_WITHDRAWAL,
  RING_COSIGN_DEPOSITS,
  RING_COSIGN_TRANSFERS,
  RING_COSIGN_WITHDRAWALS,
  type RingCoSigner,
  type RingPolicy,
} from "../protocol/codec/ring-codecs.js";
import { RingError } from "../protocol/error.js";
import { fetchRingCoSignerRecord } from "../protocol/membership/config.js";
import { ringCoSignerAddress } from "../protocol/pda/index.js";
import { ApprovalMask } from "../protocol/transaction/transact.js";

const APPROVALS = RING_COSIGN_APPROVE_OUTFLOW | RING_COSIGN_APPROVE_WITHDRAWAL;

/** A transfer's economic operation, merge and delegate demand nothing. */
export interface CoSignOperation {
  /** Clear under the statement's `no_spend`. */
  readonly spendsNote: boolean;
  /** `RING_COSIGN_DEPOSITS` and `RING_COSIGN_WITHDRAWALS` of its public legs. */
  readonly publicLegs: number;
  /** The statement's proven bits. */
  readonly approval: number;
}

export interface CoSignDemand {
  /** `RING_COSIGN_*` bits. */
  readonly classes: number;
}

export interface CoSignRequirement {
  /** Demanded classes no record covered yet. */
  readonly uncovered: number;
}

/** A demanded signer and its `CoSigner` record, the pair ahead of the SPP accounts. */
export interface RingCoSignerAccounts {
  readonly signer: Address;
  readonly record: Address;
}

export const NO_DEMAND: CoSignDemand = Object.freeze({ classes: 0 });
export const DEPOSIT_DEMAND: CoSignDemand = Object.freeze({ classes: RING_COSIGN_DEPOSITS });

/** Rust `ApprovalMask::classes`. */
export function approvalClasses(approval: number): number {
  return (
    ((approval & ApprovalMask.outflow) !== 0 ? RING_COSIGN_APPROVE_OUTFLOW : 0) |
    ((approval & ApprovalMask.withdrawal) !== 0 ? RING_COSIGN_APPROVE_WITHDRAWAL : 0)
  );
}

/** Rust `CoSignOperation::demand`. */
export function operationDemand(operation: CoSignOperation): CoSignDemand {
  return Object.freeze({
    classes:
      (operation.spendsNote ? RING_COSIGN_TRANSFERS : 0) |
      operation.publicLegs |
      approvalClasses(operation.approval),
  });
}

/** The public leg classes of `transfers`, a deposit leg adds `DEPOSITS`, a withdrawal `WITHDRAWALS`. */
export function publicLegClasses(transfers: readonly Readonly<{ isDeposit: boolean }>[]): number {
  return transfers.reduce(
    (classes, transfer) =>
      classes | (transfer.isDeposit ? RING_COSIGN_DEPOSITS : RING_COSIGN_WITHDRAWALS),
    0,
  );
}

/** Rust `CoSignDemand::requirement`, a class with no record drops out, an approval class fails closed. */
export function demandRequirement(
  demand: CoSignDemand,
  ring: Pick<RingPolicy, "coSignerClasses">,
): CoSignRequirement {
  const covered = ring.coSignerClasses ?? 0;
  const missing = demand.classes & APPROVALS & ~covered;
  if (missing !== 0)
    throw new RingError("RING_APPROVER_MISSING", { details: { classes: missing } });
  return Object.freeze({ uncovered: demand.classes & covered });
}

/** Rust `CoSignRequirement::cover`, an unrelated or repeated record covers nothing and is refused. */
export function coverRequirement(
  requirement: CoSignRequirement,
  record: Pick<RingCoSigner, "scope" | "signer">,
): CoSignRequirement {
  if ((record.scope & requirement.uncovered) === 0)
    throw new RingError("RING_COSIGNER_OUT_OF_SCOPE", {
      details: { signer: record.signer, scope: record.scope, uncovered: requirement.uncovered },
    });
  return Object.freeze({ uncovered: requirement.uncovered & ~record.scope });
}

/** Every supplied signer covers a demanded class, each class ends covered, at most `MAX_CO_SIGNERS` by construction. */
export async function resolveRingCoSigners(
  input: Readonly<{
    client: Pick<ChainReader, "getAccount">;
    ringProgramId: Address;
    config: Pick<RingPolicy, "coSignerClasses">;
    demand: CoSignDemand;
    supplied: readonly Address[];
    /** Empty on the anonymous and delegate rails. */
    ownerSigners: readonly Address[];
    delegate?: Address;
  }>,
  context?: RequestContext,
): Promise<readonly RingCoSignerAccounts[]> {
  const { client, ringProgramId, ownerSigners, delegate } = input;
  let requirement = demandRequirement(input.demand, input.config);
  const resolved: RingCoSignerAccounts[] = [];
  for (const signer of input.supplied) {
    // Rust `CoSignerIsOwner` and `CoSignerIsDelegate`, dual control needs a second key.
    if (ownerSigners.includes(signer)) throw coSignerRequired("coSignerIsOwner", signer);
    if (signer === delegate) throw coSignerRequired("coSignerIsDelegate", signer);
    const record = await fetchRingCoSignerRecord(client, ringProgramId, signer, context);
    if (record === undefined) throw coSignerRequired("noRecord", signer);
    requirement = coverRequirement(requirement, record);
    resolved.push(
      Object.freeze({ signer, record: await ringCoSignerAddress(ringProgramId, signer) }),
    );
  }
  if (requirement.uncovered !== 0)
    throw new RingError("RING_COSIGNER_REQUIRED", {
      details: { reason: "missing", ringProgramId, uncovered: requirement.uncovered },
    });
  return Object.freeze(resolved);
}

function coSignerRequired(reason: string, signer: Address): RingError {
  return new RingError("RING_COSIGNER_REQUIRED", { details: { reason, signer } });
}
