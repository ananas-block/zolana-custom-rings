/** The one ring proof of a transfer, one request over the audit and policy sections, Rust `pipeline::proof`. */
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import { nonZeroHashChain, sppPrivateTxHashInput } from "@heliuslabs/zolana/internal";
import type { SppProofInputs } from "@heliuslabs/zolana/transaction";

import type {
  AnonymousTransferProofRequest,
  ConfidentialTransferProofRequest,
} from "../rpc/prover/ring.js";
import { EMPTY_RING_OPENING } from "../rpc/prover/assembly.js";
import type { PublishedSlot, RingOutputRail } from "../operations/payments/output-rail.js";
import { transferInputClass } from "../protocol/proof/transfer-shapes.js";
import type { RingRail } from "../protocol/transaction/transact.js";
import {
  anonymousSlots,
  auditEnvelope,
  deliveredSlots,
  inputOpenings,
  type SealedAudit,
} from "./audit-proof.js";
import { policyParams, type PolicyInputs, type PolicyProving } from "./policy-proof.js";

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
  }>,
): TransferProofRequest {
  const { policy, proofInputs } = input;
  const { circuit } = policy;
  const tree = proofInputs.outputTreeId;
  const inputClass = transferInputClass(circuit);
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
      outputs: deliveredSlots(input.published, tree, input.sealed.layout.keyEscrow),
      // The signer rail opens no input, every slot a dummy.
      inputs:
        input.inProof || delegate
          ? inputOpenings(proofInputs, inputClass)
          : Array.from({ length: inputClass }, () => EMPTY_RING_OPENING),
      inputChain: nonZeroHashChain(sppPrivateTxHashInput(proofInputs).inputHashes),
      sender: input.statementSender,
      senderPkHash: input.senderPkHash,
    });
  }
  return Object.freeze({
    kind: "transferAnonymous",
    ...transfer,
    outputs: anonymousSlots(input.published, tree),
    ...(circuit.family === "transferAnonymousEntry"
      ? { senderKey: input.sender.signingPublicKey.confidentialViewTag() }
      : {}),
    inputs: inputOpenings(proofInputs, inputClass),
    partyIdentities: input.partyIdentities,
  });
}
