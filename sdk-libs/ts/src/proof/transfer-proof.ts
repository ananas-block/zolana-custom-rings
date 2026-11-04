/** The one ring proof of a transfer, one request over the audit and policy sections. */
import { hashChain, ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { randomBlinding, type X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type {
  ProofInputUtxo,
  ProofOutputUtxo,
  SppProofInputs,
} from "@heliuslabs/zolana/transaction";

import type { TransferProofRequest } from "../rpc/prover/ring.js";
import type { RingOutputRail } from "../operations/payments/output-rail.js";
import {
  fittedSpend,
  frameKeyShape,
  ownerSignerCapacity,
  ringTransferCircuit,
  signerSlots,
  type TransferAddresses,
  type TransferKeyCircuit,
  type TransferSpend,
} from "../protocol/proof/transfer-shapes.js";
import { ANONYMOUS_PARTIES, type RingRail } from "../protocol/transaction/transact.js";
import { RingError } from "../protocol/error.js";
import {
  auditEnvelope,
  entryOpenings,
  inputOpenings,
  outputOpenings,
  type SealedAudit,
} from "./audit-proof.js";
import {
  approvalTotalsOf,
  policyParams,
  type PolicyInputs,
  type PolicyProving,
} from "./policy-proof.js";
import { approvalOpeningOf, type ApprovalOpening } from "../protocol/membership/approval-totals.js";
import { signerDataCountsOf } from "../protocol/membership/signer-data-counts.js";

/** The key a transfer proves under, `wideOwners` the frame flag naming its rows. */
export interface TransferKeySelection {
  readonly circuit: TransferKeyCircuit;
  readonly wideOwners: boolean;
}

/** Refuses a transaction past the account bound before proving, picks the narrowest rows holding every owner. */
export function selectTransferKey(
  input: Readonly<{
    spend: TransferSpend;
    addresses: TransferAddresses;
    /** The published owner signers, hidden and in-proof owners take no address. */
    ownerSigners: number;
  }>,
): TransferKeySelection {
  const { spend, addresses, ownerSigners } = input;
  const capacity = ownerSignerCapacity(addresses);
  if (ownerSigners > capacity)
    throw new RingError("RING_TRANSFER_PAST_ACCOUNT_BOUND", {
      details: { ownerSigners, capacity, ...addresses },
    });
  const fitted = fittedSpend(spend);
  const circuit = ringTransferCircuit(fitted);
  if (circuit === undefined) throw unkeyed(fitted);
  return Object.freeze({ circuit, wideOwners: fitted.wide });
}

function unkeyed(spend: TransferSpend): RingError {
  const maximum = frameKeyShape(spend)?.owners;
  if (maximum !== undefined && spend.owners > maximum)
    return new RingError("RING_TOO_MANY_OWNERS", {
      details: { owners: spend.owners, maximum },
    });
  return new RingError("RING_CATALOG_KEY_MISSING", {
    details: {
      rail: spend.rail,
      inputs: spend.inputs,
      outputs: spend.outputs,
      legs: spend.legs,
    },
  });
}

export type { TransferProofRequest };

/** A frame's digest and what opens it, Rust `Frame::approval_opening`. */
export interface TransferApproval {
  readonly digest: Bytes32;
  readonly opening: ApprovalOpening;
}

/**
 * A blinder per attempt, the digest hides the totals only under one. Drawn as 31 bytes, so it stays
 * below the field for every draw and the chain can never reject or reduce it. The outputs and legs
 * read here are the ones sealing keeps, the auditor message changes neither.
 */
export function freshTransferApproval(proofInputs: SppProofInputs): TransferApproval {
  const totals = approvalTotalsOf(proofInputs, proofInputs.checkShape().outputs);
  const blinder = randomBlinding();
  return Object.freeze({
    digest: totals.commitment(blinder),
    opening: approvalOpeningOf(totals, blinder),
  });
}

/** The statement's element over the run `signers` binds and the slots SPP publishes, refused where the circuit has no solution. */
export function ownerDataCounts(
  run: readonly Bytes32[],
  outputs: readonly ProofOutputUtxo[],
): bigint {
  const counts = signerDataCountsOf(
    run,
    outputs.flatMap((output) =>
      output.isDummy() || output.ownerAddress === undefined || output.dataHash === undefined
        ? []
        : [
            {
              ownerIdentity: output.ownerAddress.signingPublicKey.ownerProofInputHash(),
              dataHash: output.dataHash,
            },
          ],
    ),
  );
  if (counts === undefined)
    throw new RingError("RING_TRANSACT_DATA_INVALID", {
      details: { reason: "InvalidSignerDataCounts" },
    });
  return counts;
}

/** Mirror `PrivateTxHash`, no chain folds an empty list. */
function addressChainOf(proofInputs: SppProofInputs): Bytes32 {
  return hashChain(
    proofInputs.inputUtxos.filter((input) => input.isAddress()).map((input) => input.nullifier()),
  );
}

/** The request of the key the frame selects, every section over the same slots. */
export function transferProofRequest(
  input: Readonly<{
    rail: RingOutputRail;
    ringRail: RingRail;
    sealed: SealedAudit;
    /** `m`. */
    outputCount: number;
    /** The spent notes in SPP order, compact padding left out. */
    inputs: readonly ProofInputUtxo[];
    proofInputs: SppProofInputs;
    auditor: X25519PublicKey;
    policy: PolicyInputs;
    proving: PolicyProving;
    publicInputHash: Bytes32;
    privateTxHash: Bytes32;
    /** The in-proof owner, zero on every other rail. */
    sender: Bytes32;
    inProof: boolean;
    publicOwners: boolean;
    /** Payer, each co-signer and exit destination, zero when absent, unread off the anonymous frame. */
    partyIdentities: readonly Bytes32[];
    /** SPP's owner signer run by owner identity, in-proof and authority bind none. */
    signers: readonly Bytes32[];
    /** Zeros when the frame discloses no totals, a zero digest opens nothing. */
    approval?: TransferApproval;
  }>,
): TransferProofRequest {
  const { policy, proofInputs, inputs, signers } = input;
  const { circuit } = policy;
  const inputClass = circuit.class;
  const entry = input.sealed.audit.entry;
  const anonymousFrame = input.ringRail === "anonymous" || input.ringRail === "anonymousDelegate";
  return Object.freeze({
    kind: "transfer",
    publicInputHash: input.publicInputHash,
    ...auditEnvelope({
      rail: input.rail,
      sealed: input.sealed,
      firstNullifier: proofInputs.firstNullifier(),
      auditor: input.auditor,
    }),
    approvalMask: policy.approvalMask,
    approvalTotals: input.approval?.digest ?? ZERO_32,
    approvalBlinder: input.approval?.opening.blinder ?? ZERO_32,
    outputCount: input.outputCount,
    // Every slot of the key's capacity, an omitted suffix runs its gadgets over its own proof output.
    outputs: outputOpenings(proofInputs.outputs, proofInputs.outputTreeId, circuit.outputs),
    inputCount: inputs.length,
    inputs: inputOpenings(inputs, inputClass),
    entries: entry ? entryOpenings(inputs, inputClass) : [],
    signerCount: signers.length,
    signerDataCounts: ownerDataCounts(signers, proofInputs.outputs),
    signers: [
      ...signers,
      ...Array.from({ length: Math.max(0, signerSlots(circuit) - signers.length) }, () => ZERO_32),
    ],
    rows: policy.rows,
    privateTxHash: input.privateTxHash,
    privateTxBlinding: proofInputs.privateTxBlinding(),
    addressChain: addressChainOf(proofInputs),
    ...policy.tracking,
    ...policyParams(policy, input.proving),
    inProof: input.inProof,
    hidden: input.ringRail === "anonymous" && !input.publicOwners,
    delegate: input.ringRail === "delegate" || input.ringRail === "anonymousDelegate",
    sender: input.sender,
    partyIdentities: anonymousFrame
      ? [
          ...input.partyIdentities,
          ...Array.from(
            { length: Math.max(0, ANONYMOUS_PARTIES - input.partyIdentities.length) },
            () => ZERO_32,
          ),
        ]
      : Array.from({ length: ANONYMOUS_PARTIES }, () => ZERO_32),
  });
}
