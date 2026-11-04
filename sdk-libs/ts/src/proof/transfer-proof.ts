/** The one ring proof of a transfer, one request over the audit and policy sections. */
import { ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { ProofInputUtxo, SppProofInputs } from "@heliuslabs/zolana/transaction";

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
import { policyParams, type PolicyInputs, type PolicyProving } from "./policy-proof.js";

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
    approvalTotals: ZERO_32,
    approvalBlinder: ZERO_32,
    outputCount: input.outputCount,
    // Every slot of the key's capacity, an omitted suffix runs its gadgets over its own proof output.
    outputs: outputOpenings(proofInputs.outputs, proofInputs.outputTreeId, circuit.outputs),
    inputCount: inputs.length,
    inputs: inputOpenings(inputs, inputClass),
    entries: entry ? entryOpenings(inputs, inputClass) : [],
    signerCount: signers.length,
    signers: [
      ...signers,
      ...Array.from({ length: Math.max(0, signerSlots(circuit) - signers.length) }, () => ZERO_32),
    ],
    rows: policy.rows,
    privateTxHash: input.privateTxHash,
    privateTxBlinding: proofInputs.privateTxBlinding(),
    addressChain: ZERO_32,
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
