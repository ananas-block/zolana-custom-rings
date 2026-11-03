/** The one ring proof of a transfer, one request over the audit and policy sections, Rust `pipeline::proof`. */
import { ZERO_32 } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import type { SppProofInputs } from "@heliuslabs/zolana/transaction";

import type {
  AnonymousTransferProofRequest,
  ConfidentialTransferProofRequest,
} from "../rpc/prover/ring.js";
import type { PublishedSlot, RingOutputRail } from "../operations/payments/output-rail.js";
import { signerSlots, transferInputClass } from "../protocol/proof/transfer-shapes.js";
import { ciphertextDigest } from "../protocol/proof/statement.js";
import type { RingOutput, RingRail } from "../protocol/transaction/transact.js";
import { RingError } from "../protocol/error.js";
import {
  anonymousSlots,
  auditEnvelope,
  deliveredSlots,
  inputOpenings,
  type SealedAudit,
} from "./audit-proof.js";
import { policyParams, type PolicyInputs, type PolicyProving } from "./policy-proof.js";

/** One slot per key capacity, an omitted suffix runs its gadgets over its own proof output. */
function paddedSlots(
  published: readonly PublishedSlot[],
  proofInputs: SppProofInputs,
): readonly PublishedSlot[] {
  return proofInputs.outputs.map(
    (output, slotIndex): PublishedSlot =>
      published[slotIndex] ?? { output, slotIndex, wire: OMITTED_WIRE },
  );
}

/** Never framed, its zero hash is what the statement fills past `m`. */
const OMITTED_WIRE: RingOutput = Object.freeze({
  kind: "change",
  hash: ZERO_32,
  tag: ZERO_32,
});

export type TransferProofRequest = ConfidentialTransferProofRequest | AnonymousTransferProofRequest;

/** The request of the key the frame selects, every section over the same slots, Rust `Assembled::request`. */
export function transferProofRequest(
  input: Readonly<{
    rail: RingOutputRail;
    ringRail: RingRail;
    sealed: SealedAudit;
    published: readonly PublishedSlot[];
    publishedInputs: number;
    proofInputs: SppProofInputs;
    sender: ShieldedAddress;
    auditor: X25519PublicKey;
    policy: PolicyInputs;
    proving: PolicyProving;
    publicInputHash: Bytes32;
    privateTxHash: Bytes32;
    /** The statement's sender identity, zero where the rail names none. */
    statementSender: Bytes32;
    senderPkHash: Bytes32;
    inProof: boolean;
    partyIdentities: readonly [Bytes32, Bytes32, Bytes32];
    /** SPP's owner signer run by owner identity, in-proof, authority and entry bind none. */
    signers: readonly Bytes32[];
    /** Every reply in slot order, absent without the flag. */
    replies?: Uint8Array;
    /** Absent off the anonymous rail. */
    senderBundleTag?: Bytes32;
  }>,
): TransferProofRequest {
  const { policy, proofInputs } = input;
  const { circuit } = policy;
  const tree = proofInputs.outputTreeId;
  const inputClass = transferInputClass(circuit);
  const slots = signerSlots(circuit);
  const transfer = {
    publicInputHash: input.publicInputHash,
    ...auditEnvelope({
      rail: input.rail,
      sealed: input.sealed,
      proofInputs,
      auditor: input.auditor,
    }),
    exempt: policy.exempt,
    approvalRequired: policy.approvalRequired,
    inputCount: input.publishedInputs,
    outputCount: input.published.length,
    signerCount: input.signers.length,
    signers: [
      ...input.signers,
      ...Array.from({ length: Math.max(0, slots - input.signers.length) }, () => ZERO_32),
    ],
    privateTxHash: input.privateTxHash,
    privateTxBlinding: proofInputs.privateTxBlinding(),
    ...policyParams(policy, input.proving),
  };
  if (circuit.family === "transferConfidential") {
    const delegate = input.ringRail === "delegate";
    return Object.freeze({
      kind: "transferConfidential",
      ...transfer,
      inProof: input.inProof,
      delegate,
      outputs: deliveredSlots(
        paddedSlots(input.published, proofInputs),
        tree,
        input.sealed.layout.keyEscrow,
      ),
      // Every rail opens every slot, one list feeds the evidence and the transaction binding.
      inputs: inputOpenings(proofInputs, inputClass),
      sender: input.statementSender,
      senderPkHash: input.senderPkHash,
    });
  }
  const address = policy.senderAddress;
  if (address === undefined)
    throw new RingError("RING_ADDRESS_NOT_ENROLLED", { details: { reason: "sender" } });
  return Object.freeze({
    kind: "transferAnonymous",
    ...transfer,
    outputs: anonymousSlots(paddedSlots(input.published, proofInputs), tree, policy.slotBindings),
    senderNullifierPk: address.nullifierPk,
    senderViewingKey: address.viewingU,
    senderAddressRevision: address.addressRevision,
    senderBundleTag: input.senderBundleTag ?? ZERO_32,
    replyDigest: input.replies === undefined ? ZERO_32 : ciphertextDigest(input.replies),
    ...(circuit.family === "transferAnonymousEntry"
      ? { senderKey: input.sender.signingPublicKey.confidentialViewTag() }
      : {}),
    inputs: inputOpenings(proofInputs, inputClass),
    partyIdentities: input.partyIdentities,
  });
}
