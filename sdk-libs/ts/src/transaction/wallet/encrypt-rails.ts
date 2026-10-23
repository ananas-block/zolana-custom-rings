import { RING_SPEND_COUNTERS_SLOT_INDEX } from "../../interface/constants.js";
import {
  addressBytes,
  hashBytes,
  bigIntToBytes,
  X25519_PUBLIC_KEY_LENGTH,
  rightAlign,
  ZERO_32,
} from "@heliuslabs/zolana/internal";
import {
  DUMMY_DOMAIN,
  UTXO_DOMAIN,
  treeIdField,
  type MessageData,
} from "@heliuslabs/zolana/interface";
import {
  type Bytes16,
  type Bytes32,
  type Bytes33,
  ShieldedAddress,
  type ViewingKey,
  TransactionError,
  SOL_MINT,
} from "@heliuslabs/zolana";
import { randomSalt, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  encodeConfidentialSlots,
  createProofOutput,
  type ProofOutputUtxo,
  type TreeId,
  type AssetRegistry,
  type EncryptedTransfer,
} from "@heliuslabs/zolana/transaction";
import {
  auditorMessageData,
  encryptTransactionViewingSecret,
  type AuditOutputOpening,
} from "../../keypair/audit.js";

/** `txViewingSecret` is what the auditor key opens. It exists for the ring's own prover and is wiped after it. */
export interface AuditWitness {
  readonly txViewingSecret: Bytes32;
  readonly ephemeralSecret: Bytes32;
}

export interface EncryptedCustomRingTransfer extends EncryptedTransfer {
  readonly auditorMessage: MessageData;
  readonly sealedMessages: readonly MessageData[];
  readonly audit: AuditWitness;
}

/** Plaintext sealed to the transaction viewing key under its own slot index. */
export interface SealedMessageInput {
  readonly viewTag: Bytes32;
  readonly plaintext: Uint8Array;
  readonly slotIndex: number;
}

/**
 * The caller wipes the returned audit secrets after proving. `recordOutputIndex`
 * names the last output as the spend record carrier, encrypted to the
 * transaction viewing key itself. `counterMessage` is the protocol counter seal,
 * never a caller message channel.
 */
export function encryptCustomRingTransfer(
  tx: ViewingKey,
  input: Readonly<{
    outputs: readonly ProofOutputUtxo[];
    assets: AssetRegistry;
    auditorPublicKey: X25519PublicKey;
    outputTreeId: TreeId;
    recordOutputIndex?: number;
    sealedMessages?: readonly SealedMessageInput[];
    counterMessage?: Omit<SealedMessageInput, "slotIndex">;
  }>,
): EncryptedCustomRingTransfer {
  let txViewingSecret: Bytes32 | undefined;
  let ephemeralSecret: Bytes32 | undefined;
  try {
    const salt = randomSalt();
    txViewingSecret = tx.secretBytes();
    const recipient = tx.publicKey();
    const outputs = recordCarrierOutputs(
      input.outputs,
      input.recordOutputIndex === undefined
        ? undefined
        : { index: input.recordOutputIndex, recipient },
    );
    const encryption = encryptTransactionViewingSecret(txViewingSecret, input.auditorPublicKey, {
      salt,
      outputs: outputs.map((output) => auditOutputOpening(output, input.outputTreeId)),
    });
    ephemeralSecret = encryption.ephemeralSecret;
    const callerMessages = (input.sealedMessages ?? []).map((message) => ({
      slotIndex: message.slotIndex,
      plaintext: message.plaintext,
      viewTag: message.viewTag,
    }));
    checkDistinctSlots(outputs.length, callerMessages);
    const outbound = [
      ...callerMessages,
      ...(input.counterMessage === undefined
        ? []
        : [{ ...input.counterMessage, slotIndex: RING_SPEND_COUNTERS_SLOT_INDEX }]),
    ];
    const sealedMessages: readonly MessageData[] = outbound.map((message) => {
      const ciphertext = tx.encryptSlot(recipient, message.plaintext, salt, message.slotIndex);
      const body = new Uint8Array(X25519_PUBLIC_KEY_LENGTH + ciphertext.length);
      body.set(recipient.toBytes(), 0);
      body.set(ciphertext, X25519_PUBLIC_KEY_LENGTH);
      return { viewTag: message.viewTag, data: body };
    });
    const encrypted = {
      txViewingPublicKey: recipient,
      salt,
      payload: encodeConfidentialSlots(outputs, input.assets, tx, salt),
      auditorMessage: auditorMessageData(encryption.message, input.auditorPublicKey),
      sealedMessages,
      audit: Object.freeze({ txViewingSecret, ephemeralSecret }),
    };
    // The finally must not wipe the secrets the returned object owns.
    txViewingSecret = undefined;
    ephemeralSecret = undefined;
    return encrypted;
  } finally {
    txViewingSecret?.fill(0);
    ephemeralSecret?.fill(0);
  }
}

function auditOutputOpening(output: ProofOutputUtxo, outputTreeId: TreeId): AuditOutputOpening {
  const dummy = output.isDummy();
  return Object.freeze({
    domain: rightAlign(Uint8Array.of(dummy ? DUMMY_DOMAIN : UTXO_DOMAIN)),
    treeId: treeIdField(outputTreeId),
    ownerHash: dummy ? ZERO_32 : output.ownerHash(),
    asset: dummy ? ZERO_32 : (hashBytes(addressBytes(output.asset)) as Bytes32),
    amount: dummy ? ZERO_32 : (bigIntToBytes(output.amount) as Bytes32),
    blinding: output.blinding,
    dataHash: dummy ? ZERO_32 : (output.dataHash ?? ZERO_32),
    ringDataHash: dummy ? ZERO_32 : (output.ringDataHash ?? ZERO_32),
    ringProgramId:
      dummy || output.ringProgramId === undefined
        ? ZERO_32
        : (hashBytes(addressBytes(output.ringProgramId)) as Bytes32),
  });
}

/** The recipient viewing key does not affect the UTXO commitment. */
function recordCarrierOutputs(
  outputs: readonly ProofOutputUtxo[],
  carrier: Readonly<{ index: number; recipient: X25519PublicKey }> | undefined,
): readonly ProofOutputUtxo[] {
  if (carrier === undefined) return outputs;
  const { index, recipient } = carrier;
  const output = outputs[index];
  const owner = output?.ownerAddress;
  if (
    !Number.isInteger(index) ||
    index < 0 ||
    index !== outputs.length - 1 ||
    output === undefined ||
    owner === undefined
  ) {
    throw new TransactionError("TRANSACTION_INVALID_OUTPUT_POSITION", {
      index,
    });
  }
  if (
    owner.signingPublicKey.signatureType() !== "pda" ||
    output.asset !== SOL_MINT ||
    output.amount !== 0n ||
    output.ringProgramId !== undefined ||
    output.dataHash === undefined ||
    output.data.records().length !== 0
  )
    throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH");
  return outputs.map((candidate, position) =>
    position !== index
      ? candidate
      : createProofOutput({
          ...output,
          ownerAddress: ShieldedAddress.fromPublicKeys(
            owner.signingPublicKey,
            owner.nullifierPublicKey,
            recipient,
          ),
        }),
  );
}

/** One keystream per slot under a fixed key and salt. */
function checkDistinctSlots(
  outputCount: number,
  messages: readonly Readonly<{ slotIndex: number }>[],
): void {
  const slots = new Set<number>([
    RING_SPEND_COUNTERS_SLOT_INDEX,
    ...Array.from({ length: outputCount }, (_, index) => index),
  ]);
  for (const message of messages) {
    if (slots.has(message.slotIndex)) {
      throw new TransactionError("TRANSACTION_DUPLICATE_SLOT_INDEX", {
        slotIndex: message.slotIndex,
      });
    }
    slots.add(message.slotIndex);
  }
}

/** `data` is the recipient key followed by the slot ciphertext. */
export function openSealedMessage(
  tx: ViewingKey,
  input: Readonly<{ salt: Bytes16; slotIndex: number; data: Uint8Array }>,
): Uint8Array {
  const recipient = X25519PublicKey.fromBytes(
    input.data.slice(0, X25519_PUBLIC_KEY_LENGTH) as Bytes33,
  );
  const ciphertext = input.data.slice(X25519_PUBLIC_KEY_LENGTH);
  return tx.decryptSlotEphemeral(recipient, ciphertext, input.salt, input.slotIndex);
}
