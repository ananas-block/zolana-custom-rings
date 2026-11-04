/** The one ring proof of a transfer, one request over the audit and policy sections. */
import { ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { ProofInputUtxo, SppProofInputs } from "@heliuslabs/zolana/transaction";

import type {
  AnonymousTransferProofRequest,
  ConfidentialTransferProofRequest,
} from "../rpc/prover/ring.js";
import type { RingOutputRail } from "../operations/payments/output-rail.js";
import {
  familyShapes,
  ownerSignerCapacity,
  ringTransferCircuit,
  signerSlots,
  transferInputClass,
  transferShapes,
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
  const circuit = ringTransferCircuit(spend);
  if (circuit === undefined) throw unkeyed(spend);
  const narrowest = familyShapes(circuit.family).find((shape) => shape.outputs === circuit.outputs)
    ?.owners[0];
  return Object.freeze({ circuit, wideOwners: circuit.owners !== narrowest });
}

/** A subject past every keyed row names the rows, any other miss names the shape. */
function unkeyed(spend: TransferSpend): RingError {
  const shape = transferShapes(spend.rail, spend.spendsDefaultRing)?.find(
    (entry) => entry.outputs === spend.outputs,
  );
  const maximum = shape?.owners.at(-1);
  if (maximum !== undefined && spend.owners > maximum)
    return new RingError("RING_TOO_MANY_OWNERS", {
      details: { owners: spend.owners, maximum },
    });
  return new RingError("RING_TRANSACT_DATA_INVALID", {
    details: {
      reason: "RingShapeUnkeyed",
      rail: spend.rail,
      inputs: spend.inputs,
      outputs: spend.outputs,
      legs: spend.legs,
    },
  });
}

export type TransferProofRequest = ConfidentialTransferProofRequest | AnonymousTransferProofRequest;

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
    /** Payer, five co-signers and exit destination, zero when absent, unread off the anonymous frame. */
    partyIdentities: readonly Bytes32[];
    /** SPP's owner signer run by owner identity, in-proof and authority bind none. */
    signers: readonly Bytes32[];
  }>,
): TransferProofRequest {
  const { policy, proofInputs, inputs, signers } = input;
  const { circuit } = policy;
  const inputClass = transferInputClass(circuit);
  const entry = input.sealed.audit.entry;
  const transfer = {
    publicInputHash: input.publicInputHash,
    ...auditEnvelope({
      rail: input.rail,
      sealed: input.sealed,
      firstNullifier: proofInputs.firstNullifier(),
      auditor: input.auditor,
    }),
    approvalMask: policy.approvalMask,
    outputCount: input.outputCount,
    // Every slot of the key's capacity, an omitted suffix runs its gadgets over its own proof output.
    outputs: outputOpenings(proofInputs.outputs, proofInputs.outputTreeId),
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
    ...policy.tracking,
    ...policyParams(policy, input.proving),
  };
  if (circuit.family === "transferConfidential" || circuit.family === "transferConfidentialEntry")
    return Object.freeze({
      kind: "transferConfidential",
      ...transfer,
      inProof: input.inProof,
      delegate: input.ringRail === "delegate",
      sender: input.sender,
    });
  return Object.freeze({
    kind: "transferAnonymous",
    ...transfer,
    publicOwners: input.publicOwners,
    delegate: input.ringRail === "anonymousDelegate",
    partyIdentities: [
      ...input.partyIdentities,
      ...Array.from(
        { length: Math.max(0, ANONYMOUS_PARTIES - input.partyIdentities.length) },
        () => ZERO_32,
      ),
    ],
  });
}
