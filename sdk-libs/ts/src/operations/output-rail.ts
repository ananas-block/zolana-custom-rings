/** The ring output rails, mirrors Rust `zolana-ring-transaction` over the ring program's expansion. */
import {
  encryptConfidential,
  equalBytes,
  isCanonicalField,
  ZERO_32,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes32, TransactOutput } from "@heliuslabs/zolana/interface";
import { randomSalt, ViewingKey } from "@heliuslabs/zolana/keypair";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  createExternalData,
  Data,
  ProofInputUtxo,
  SOL_ASSET_ID,
  SppProofInputs,
  TransactionError,
  type AssetRegistry,
  type PreparedTransfer,
  type ProofOutputUtxo,
} from "@heliuslabs/zolana/transaction";

import {
  encodeRingPacked,
  encryptRingPacked,
  readRingOutput,
  RECIPIENT_KEY_LEN,
  RING_DELIVERED_BODY_LEN,
  RingScheme,
  sealDeliveredBody,
} from "../protocol/output.js";
import {
  deliveredSlotSecret,
  ringTag,
  ringTagField,
  ringTagFromOwnerTag,
  type TagIndex,
} from "../crypto/ring-stream.js";
import { withOutputFields } from "../protocol/proof-output.js";
import { anonymousRingData, ringBlindedOutputs, ringBlindingSeed } from "../crypto/blinding.js";
import { RingError } from "../protocol/error.js";
import { ringTransactOutput, type RingOutput } from "../protocol/transact.js";

/** How the ring outputs of one transfer reach their recipients, Rust `RingDelivery`. */
export type RingDelivery =
  /** Confidential capacity 2 and 4 and the delegate rail at those capacities, scheme 11. */
  | Readonly<{ kind: "packed" }>
  /** Capacity 8 and 16, scheme 10 delivered to the owner's viewing key. */
  | Readonly<{ kind: "delivered" }>
  /** Scheme 9 under a stream tag, each payment delivered to its ring address key. */
  | Readonly<{ kind: "anonymous"; slots: AnonymousSlots }>;

/** The proven stream position of one anonymous payment, Rust `StreamPosition`. */
export type StreamPosition = Readonly<{ kind: "inbox" | "pair"; index: TagIndex }>;

/** One anonymous payment, Rust `StreamPayment`. */
export interface StreamPayment {
  /** The ring address key its body opens under. */
  readonly recipient: X25519PublicKey;
  readonly tag: Bytes16;
  readonly position: StreamPosition;
}

/** One slot of an anonymous transfer as its audit proof places it, Rust `AnonymousSlot`. */
export type AnonymousSlot =
  | Readonly<{ kind: "payment"; payment: StreamPayment }>
  /** The sender's change under a free tag, delivered to its ring change key. */
  | Readonly<{ kind: "change"; tag: Bytes16 }>
  | Readonly<{ kind: "exit" }>
  /** Padding under a free tag. */
  | Readonly<{ kind: "dummy"; tag: Bytes16 }>;

/** The payments of an anonymous transfer by final slot index, Rust `AnonymousSlots`. */
export class AnonymousSlots {
  readonly changeKey: X25519PublicKey;
  readonly #payments: ReadonlyMap<number, StreamPayment>;
  readonly #ringAddressKeys: readonly X25519PublicKey[];
  /** Drawn ahead, a change slot's ring secret binds its tag before the owner tags resolve. */
  readonly #freeTags: readonly Bytes16[];

  private constructor(
    changeKey: X25519PublicKey,
    payments: ReadonlyMap<number, StreamPayment>,
    ringAddressKeys: readonly X25519PublicKey[],
    freeTags: readonly Bytes16[],
  ) {
    this.changeKey = changeKey;
    this.#payments = payments;
    this.#ringAddressKeys = ringAddressKeys;
    this.#freeTags = freeTags;
    Object.freeze(this);
  }

  /** `changeKey` is the sender's ring change key, its change needs no secret to find. */
  static create(changeKey: X25519PublicKey, slots: number): AnonymousSlots {
    return new AnonymousSlots(changeKey, new Map(), [], Array.from({ length: slots }, freeTag));
  }

  /** Refuses a taken slot, a repeated tag and a second pair payment. */
  withPayment(slotIndex: number, payment: StreamPayment): AnonymousSlots {
    const payments = [...this.#payments.values()];
    if (
      this.#payments.has(slotIndex) ||
      payments.some((other) => equalBytes(other.tag, payment.tag)) ||
      (payment.position.kind === "pair" && payments.some((other) => other.position.kind === "pair"))
    )
      throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
    return new AnonymousSlots(
      this.changeKey,
      new Map([...this.#payments, [slotIndex, Object.freeze({ ...payment })]]),
      [...this.#ringAddressKeys, payment.recipient],
      this.#freeTags,
    );
  }

  /** The sender's own ring address keys, no exit may name one. */
  withRingAddressKeys(keys: readonly X25519PublicKey[]): AnonymousSlots {
    return new AnonymousSlots(
      this.changeKey,
      this.#payments,
      [...this.#ringAddressKeys, ...keys],
      this.#freeTags,
    );
  }

  payment(slotIndex: number): StreamPayment | undefined {
    return this.#payments.get(slotIndex);
  }

  /** Rust `AnonymousSlots::slot`, an output the plan does not name is change, an exit or padding. */
  slot(output: ProofOutputUtxo, sender: ShieldedAddress, slotIndex: number): AnonymousSlot {
    const payment = this.#payments.get(slotIndex);
    const owner = output.ownerAddress;
    if (owner === undefined || output.ringProgramId === undefined) {
      if (payment !== undefined)
        throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
      if (owner === undefined)
        return Object.freeze({ kind: "dummy", tag: this.#freeTag(slotIndex) });
      if (this.#ringAddressKeys.some((key) => key.equals(owner.viewingPublicKey)))
        throw new RingError("RING_ADDRESS_EXIT", { details: { slotIndex } });
      return Object.freeze({ kind: "exit" });
    }
    if (payment !== undefined) {
      if (!payment.recipient.equals(owner.viewingPublicKey))
        throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
      return Object.freeze({ kind: "payment", payment });
    }
    if (equalBytes(owner.toBytes(), sender.toBytes()))
      return Object.freeze({ kind: "change", tag: this.#freeTag(slotIndex) });
    throw new RingError("RING_UNPLANNED_OUTPUT", { details: { slotIndex } });
  }

  /** Every planned payment sits on a slot of the transaction. */
  checkPlanned(slots: number): void {
    const outside = [...this.#payments.keys()].find((index) => index >= slots);
    if (outside !== undefined)
      throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex: outside } });
  }

  #freeTag(slotIndex: number): Bytes16 {
    const tag = this.#freeTags[slotIndex];
    if (tag === undefined) throw new RingError("RING_PAYMENT_SLOT", { details: { slotIndex } });
    return tag;
  }
}

/** One published slot, its compact wire form and what its audit proof opens, Rust `PublishedSlot`. */
export interface PublishedSlot {
  readonly output: ProofOutputUtxo;
  /** The final slot index of `output`. */
  readonly slotIndex: number;
  readonly wire: RingOutput;
  /** The key a delivered or anonymous ring output's body opens under. */
  readonly recipient?: X25519PublicKey;
  /** Set on the anonymous rail. */
  readonly anonymous?: AnonymousSlot;
}

/** How a slot publishes, by rail. */
type Slot =
  | Readonly<{ kind: "ring"; recipient: X25519PublicKey; tag?: Bytes16 }>
  | Readonly<{ kind: "exit" }>
  | Readonly<{ kind: "dummy"; tag?: Bytes16 }>
  | Readonly<{ kind: "compact" }>;

/** The payload SPP binds for one final slot, as the program expands the slot's compact wire. */
type FramedSlot =
  | Readonly<{ kind: "compact" }>
  | Readonly<{ kind: "framed"; viewTag: Bytes32; data: Uint8Array }>;

/** Rust `RingOutputRail`, keyed by a transaction viewing key the caller destroys and a salt drawn per rail. */
export class RingOutputRail {
  readonly txViewingKey: ViewingKey;
  readonly salt: Bytes16;
  readonly delivery: RingDelivery;
  readonly #firstNullifier: Bytes32;

  /** `firstNullifier` is the transfer's input slot 0, padding never moves it. */
  constructor(txViewingKey: ViewingKey, firstNullifier: Bytes32, delivery: RingDelivery) {
    this.txViewingKey = txViewingKey;
    this.salt = randomSalt();
    this.delivery = delivery;
    this.#firstNullifier = firstNullifier;
    Object.freeze(this);
  }

  /** The CRDS slot secret of the ring output at `slotIndex`, the key of its body and its ring data. */
  slotSecret(recipient: X25519PublicKey, slotIndex: number): Bytes32 {
    const agreement = this.txViewingKey.ecdh(recipient);
    try {
      return deliveredSlotSecret({
        agreement,
        txViewingKey: this.txViewingKey.publicKey(),
        recipientViewingKey: recipient,
        salt: this.salt,
        outputIndex: slotIndex,
        firstNullifier: this.#firstNullifier,
      });
    } finally {
      agreement.fill(0);
    }
  }

  /** SPP's `blinding_seed`, rebuilt by any holder of the transaction key. */
  blindingSeed(): Bytes32 {
    const txViewingSecret = this.txViewingKey.secretBytes();
    try {
      return ringBlindingSeed(txViewingSecret, this.salt);
    } finally {
      txViewingSecret.fill(0);
    }
  }

  /**
   * Seals every slot of `prepared` under its own inline tag, Rust `RingOutputRail::encrypt`.
   */
  encrypt(
    input: Readonly<{
      prepared: PreparedTransfer;
      sender: ShieldedAddress;
      assets: AssetRegistry;
      instructionDiscriminator: number;
    }>,
  ): SppProofInputs {
    const { prepared, sender } = input;
    if (!equalBytes(prepared.firstNullifier, this.#firstNullifier)) throw framingError(0);
    const anonymous = this.delivery.kind === "anonymous";
    if (anonymous) this.delivery.slots.checkPlanned(prepared.shape.outputs);
    const planned = prepared.proofOutputs().map((output, slotIndex) => {
      if (!anonymous) return output;
      if (output.ringDataHash !== undefined)
        throw new RingError("RING_DELIVERED_OUTPUT_DATA", { details: { slotIndex } });
      // The anonymous circuit folds the zero tag into every padding owner.
      return output.isDummy()
        ? withOutputFields(output, { ownerTag: new Uint8Array(32) as Bytes32 })
        : output;
    });
    const outputs = ringBlindedOutputs({
      outputs: planned,
      firstNullifier: this.#firstNullifier,
      blindingSeed: this.blindingSeed(),
      ringData: planned.map((output, slotIndex) => this.#ringData(output, sender, slotIndex)),
    });
    const published: TransactOutput[] = [];
    outputs.forEach((output, slotIndex) => {
      const slot = this.#frame(output, sender, slotIndex, input.assets);
      if (output.isCompact() !== (slot.kind === "compact")) throw framingError(slotIndex);
      if (slot.kind === "compact") return;
      published.push({
        utxoHash: output.hash(prepared.outputTreeId),
        ownerTag: { kind: "inline", value: slot.viewTag },
        data: slot.data,
      });
    });
    return new SppProofInputs({
      payer: prepared.payer,
      inputUtxos: paddedInputs(prepared),
      outputs,
      externalData: createExternalData({
        instructionDiscriminator: input.instructionDiscriminator,
        interfaceTransfers: prepared.interfaceTransfers,
        txViewingPublicKey: this.txViewingKey.publicKey(),
        salt: this.salt,
        outputs: published,
        resolvedOwnerTags: published.map(({ ownerTag }) =>
          ownerTag.kind === "inline" ? ownerTag.value : ZERO_32,
        ),
        messages: [],
      }),
      blindingSeed: this.blindingSeed(),
      outputTreeId: prepared.outputTreeId,
    });
  }

  /**
   * Every published slot in order, each expanding to exactly the output the SPP proof binds, Rust
   * `RingOutputRail::published_slots`.
   */
  publishedSlots(proofInputs: SppProofInputs, sender: ShieldedAddress): readonly PublishedSlot[] {
    const published = proofInputs.externalData.outputs;
    const slots: PublishedSlot[] = [];
    proofInputs.outputs.forEach((output, slotIndex) => {
      if (output.isCompact()) return;
      const expected = published[slots.length];
      if (expected === undefined) throw framingError(slotIndex);
      const slot = this.#slot(output, sender, slotIndex);
      const wire = this.#wire(slot, expected, slotIndex);
      if (this.delivery.kind === "anonymous") {
        const ringData = this.#ringData(output, sender, slotIndex);
        if (!equalBytes(output.ringDataHash ?? ZERO_32, ringData ?? ZERO_32))
          throw framingError(slotIndex);
      }
      slots.push(
        Object.freeze({
          output,
          slotIndex,
          wire,
          ...(slot.kind === "ring" && this.delivery.kind !== "packed"
            ? { recipient: slot.recipient }
            : {}),
          ...(this.delivery.kind === "anonymous"
            ? { anonymous: this.delivery.slots.slot(output, sender, slotIndex) }
            : {}),
        }),
      );
    });
    if (slots.length !== published.length) throw framingError(proofInputs.outputs.length);
    return Object.freeze(slots);
  }

  /** The round trip through the program's expansion refuses any other framing, Rust `RingOutputRail::wire`. */
  #wire(slot: Slot, published: TransactOutput, slotIndex: number): RingOutput {
    if (published.ownerTag.kind !== "inline" || published.data === undefined)
      throw framingError(slotIndex);
    const ownerTag = published.ownerTag.value;
    const hash = published.utxoHash;
    const body = (scheme: RingScheme): Uint8Array => {
      const frame = readRingOutput(published.data ?? new Uint8Array());
      if (frame.encoding !== "encrypted" || frame.scheme !== scheme) throw framingError(slotIndex);
      return frame.body;
    };
    let wire: RingOutput;
    if (slot.kind === "compact") throw framingError(slotIndex);
    if (slot.kind === "exit") {
      wire = { kind: "exit", hash, ownerTag, payload: body(RingScheme.confidential) };
    } else {
      switch (this.delivery.kind) {
        case "packed":
          wire = {
            kind: "packed",
            hash,
            u: ownerTag,
            ciphertext: body(RingScheme.ringConfidentialPacked).subarray(RECIPIENT_KEY_LEN),
          };
          break;
        case "delivered":
          wire = {
            kind: "delivered",
            hash,
            u: ownerTag,
            body: body(RingScheme.ringConfidentialDelivered),
          };
          break;
        case "anonymous": {
          const tag = ringTagFromOwnerTag(ownerTag);
          if (tag === undefined) throw framingError(slotIndex);
          wire = { kind: "anonymous", hash, tag, body: body(RingScheme.ringAnonymous) };
          break;
        }
      }
    }
    const expanded = ringTransactOutput(wire);
    if (
      !equalBytes(expanded.utxoHash, hash) ||
      expanded.ownerTag.kind !== "inline" ||
      !equalBytes(expanded.ownerTag.value, ownerTag) ||
      !equalBytes(expanded.data ?? new Uint8Array(), published.data)
    )
      throw framingError(slotIndex);
    return Object.freeze(wire);
  }

  /** Rust `RingOutputRail::slot`. */
  #slot(output: ProofOutputUtxo, sender: ShieldedAddress, slotIndex: number): Slot {
    const delivered = this.delivery.kind !== "packed";
    if (output.isCompact()) {
      if (delivered)
        throw new RingError("RING_DELIVERED_COMPACT_PADDING", { details: { slotIndex } });
      return Object.freeze({ kind: "compact" });
    }
    // `encrypt` refuses ring data the anonymous rail did not derive.
    const carriesData =
      !output.data.isEmpty() ||
      output.dataHash !== undefined ||
      (output.ringDataHash !== undefined && this.delivery.kind !== "anonymous");
    if (delivered && !output.isDummy() && carriesData)
      throw new RingError("RING_DELIVERED_OUTPUT_DATA", { details: { slotIndex } });
    if (this.delivery.kind === "anonymous") {
      const slot = this.delivery.slots.slot(output, sender, slotIndex);
      switch (slot.kind) {
        case "payment":
          return Object.freeze({
            kind: "ring",
            recipient: slot.payment.recipient,
            tag: slot.payment.tag,
          });
        case "change":
          return Object.freeze({
            kind: "ring",
            recipient: this.delivery.slots.changeKey,
            tag: slot.tag,
          });
        case "exit":
          return Object.freeze({ kind: "exit" });
        case "dummy":
          return Object.freeze({ kind: "dummy", tag: slot.tag });
      }
    }
    if (output.isDummy()) return Object.freeze({ kind: "dummy" });
    const owner = output.ownerAddress;
    if (output.ringProgramId === undefined || owner === undefined)
      return Object.freeze({ kind: "exit" });
    return Object.freeze({ kind: "ring", recipient: owner.viewingPublicKey });
  }

  /** CRAT on an anonymous ring output, `undefined` on every other slot. */
  #ringData(
    output: ProofOutputUtxo,
    sender: ShieldedAddress,
    slotIndex: number,
  ): Bytes32 | undefined {
    const slot = this.#slot(output, sender, slotIndex);
    if (slot.kind !== "ring" || slot.tag === undefined) return undefined;
    const secret = this.slotSecret(slot.recipient, slotIndex);
    try {
      return anonymousRingData(secret, slot.tag);
    } finally {
      secret.fill(0);
    }
  }

  /** Rust `RingOutputRail::encode_slot` with the owner tag `owner_tags` resolves for the slot. */
  #frame(
    output: ProofOutputUtxo,
    sender: ShieldedAddress,
    slotIndex: number,
    assets: AssetRegistry,
  ): FramedSlot {
    const slot = this.#slot(output, sender, slotIndex);
    const zero = new Uint8Array(32) as Bytes32;
    switch (slot.kind) {
      case "compact":
        return Object.freeze({ kind: "compact" });
      case "exit": {
        const owner = output.ownerAddress;
        if (owner === undefined)
          throw new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
        const viewTag = owner.signingPublicKey.confidentialViewTag();
        const payload = encryptConfidential(
          this.txViewingKey,
          owner.viewingPublicKey,
          {
            assetId: assets.assetId(output.asset),
            amount: output.amount,
            blinding: output.blinding,
            data: output.data,
          },
          this.salt,
          slotIndex,
        );
        return framed(viewTag, { kind: "exit", hash: zero, ownerTag: viewTag, payload });
      }
      case "ring": {
        if (slot.tag === undefined && this.delivery.kind === "packed") {
          const body = encryptRingPacked(
            this.txViewingKey,
            slot.recipient,
            {
              assetId: assets.assetId(output.asset),
              amount: output.amount,
              blinding: output.blinding,
              data: output.data,
            },
            this.salt,
            slotIndex,
          );
          const u = slot.recipient.u();
          return framed(u, { kind: "packed", hash: zero, u, ciphertext: body.subarray(33) });
        }
        const secret = this.slotSecret(slot.recipient, slotIndex);
        let body: Uint8Array;
        try {
          body = sealDeliveredBody(secret, { blinding: output.blinding, amount: output.amount });
        } finally {
          secret.fill(0);
        }
        if (slot.tag !== undefined)
          return framed(ringTagField(slot.tag), {
            kind: "anonymous",
            hash: zero,
            tag: slot.tag,
            body,
          });
        const u = slot.recipient.u();
        return framed(u, { kind: "delivered", hash: zero, u, body });
      }
      case "dummy": {
        const body = randomBytes(RING_DELIVERED_BODY_LEN);
        if (slot.tag !== undefined)
          return framed(ringTagField(slot.tag), {
            kind: "anonymous",
            hash: zero,
            tag: slot.tag,
            body,
          });
        // A random key publishes as a real recipient's would.
        const key = ViewingKey.generate();
        try {
          const u = key.publicKey().u();
          if (this.delivery.kind !== "packed")
            return framed(u, { kind: "delivered", hash: zero, u, body });
          const ciphertext = this.txViewingKey.encryptSlot(
            key.publicKey(),
            encodeRingPacked({
              assetId: SOL_ASSET_ID,
              amount: 0n,
              blinding: zero,
              data: new Data(),
            }),
            this.salt,
            slotIndex,
          );
          return framed(u, { kind: "packed", hash: zero, u, ciphertext });
        } finally {
          key.destroy();
        }
      }
    }
  }
}

/** `low128` of a uniform field element, the change and padding tags no stream derives. */
export function freeTag(): Bytes16 {
  for (;;) {
    const value = randomBytes(32);
    // Below 2^254 the modulus accepts about three draws in four.
    value[0] = (value[0] ?? 0) & 0x3f;
    if (isCanonicalField(value)) return ringTag(value as Bytes32);
  }
}

function framed(viewTag: Bytes32, wire: RingOutput): FramedSlot {
  const { data } = ringTransactOutput(wire);
  if (data === undefined) throw new RingError("RING_OUTPUT_FRAMING");
  return Object.freeze({ kind: "framed", viewTag, data });
}

/** Random dummies join the last input tree and compact padding the first, as SPP reads them. */
function paddedInputs(prepared: PreparedTransfer): readonly ProofInputUtxo[] {
  const treeId = prepared.compactPadding ? prepared.inputTreeIds[0] : prepared.inputTreeIds.at(-1);
  if (treeId === undefined) throw new TransactionError("TRANSACTION_NO_INPUTS");
  const inputs = [...prepared.inputs];
  while (inputs.length < prepared.shape.inputs)
    inputs.push(
      prepared.compactPadding
        ? ProofInputUtxo.compact(treeId)
        : ProofInputUtxo.dummy(undefined, treeId),
    );
  return inputs;
}

function framingError(slotIndex: number): RingError {
  return new RingError("RING_OUTPUT_FRAMING", { details: { slotIndex } });
}

function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}
