/** Tag allocation and ring addresses of an anonymous ring, Rust `zolana_ring_client::anonymous`. */
import type { Address, Bytes16, RequestContext } from "@heliuslabs/zolana";
import { bytesKey, bytesToBigInt, U64_MAX } from "@heliuslabs/zolana/internal";
import { ShieldedAddress } from "@heliuslabs/zolana/keypair";

import { Pairing, RingAddress } from "../crypto/ring-address.js";
import {
  J_INBOX,
  J_PAIR,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  tagIndex,
  type TagIndex,
} from "../crypto/ring-stream.js";
import { RingError } from "../protocol/error.js";
import { AnonymousRingState, type PairAnchor } from "./anonymous-state.js";
import type { RingKeys } from "./ring-keys.js";

/** One payment's place in its recipient's tag streams. */
export type PaymentStream =
  | Readonly<{ kind: "inbox" }>
  | Readonly<{ kind: "pair"; anchor: PairAnchor }>;

/** The tag a payment publishes in the epoch its proof binds. */
export interface PaymentTag {
  readonly stream: PaymentStream;
  readonly epoch: bigint;
  readonly index: TagIndex;
  readonly tag: Bytes16;
}

/** The pair stream of a pinned first contact the address's rows admit, else the inbox stream, Rust `TagAllocation`. */
export class TagAllocation {
  readonly #state: AnonymousRingState;
  readonly #epoch: bigint;
  /** The inbox indexes this transaction took, by inbox key. */
  readonly #taken = new Map<string, Set<number>>();
  #paired = false;

  /** `state` is the sender's, its first contacts anchor pair payments. */
  constructor(state: AnonymousRingState, epoch: bigint) {
    this.#state = state;
    this.#epoch = epoch;
  }

  /** Each index is uniform over the ones this transaction left free, `random` draws it. */
  allocate(address: RingAddress, random: (length: number) => Uint8Array): PaymentTag {
    if (address.ringProgramId !== this.#state.ring)
      throw new RingError("RING_FOREIGN_RING", {
        details: { addressRing: address.ringProgramId, ring: this.#state.ring },
      });
    const recipient = address.recipient.viewingPublicKey;
    const anchor = this.#paired ? undefined : this.#state.pairAnchor(recipient, this.#epoch);
    if (
      anchor !== undefined &&
      address.pairing.admits(anchor.contact.asset, anchor.contact.amount)
    ) {
      const pair = pairKey(anchor.contact.slotSecret);
      try {
        // One pair slot per transaction, no index of the stream is taken yet.
        const index = draw({ taken: new Set(), size: J_PAIR }, random);
        this.#paired = true;
        const stream: PaymentStream = { kind: "pair", anchor };
        return Object.freeze({
          stream,
          epoch: this.#epoch,
          index,
          tag: pairTag(pair, this.#epoch, index),
        });
      } finally {
        pair.fill(0);
      }
    }
    const inbox = inboxKey(ringIdField(this.#state.ring), recipient);
    const taken = this.#taken.get(bytesKey(inbox)) ?? new Set<number>();
    this.#taken.set(bytesKey(inbox), taken);
    const index = draw({ taken, size: J_INBOX }, random);
    const stream: PaymentStream = { kind: "inbox" };
    return Object.freeze({
      stream,
      epoch: this.#epoch,
      index,
      tag: inboxTag(inbox, this.#epoch, index),
    });
  }
}

/** Uniform over the free indexes below `size`, over all of them once none is free, Rust `TagAllocation::draw`. */
function draw(
  stream: Readonly<{ taken: Set<number>; size: number }>,
  random: (length: number) => Uint8Array,
): TagIndex {
  const { taken, size } = stream;
  const free = Array.from({ length: size }, (_, at) => at).filter((at) => !taken.has(at));
  const pool = free.length === 0 ? Array.from({ length: size }, (_, at) => at) : free;
  const index = pool[uniformBelow(random, pool.length)] ?? 0;
  taken.add(index);
  return tagIndex(index);
}

/** A draw past the largest multiple of `bound` is drawn again, the rest are uniform, Rust `uniform_below`. */
function uniformBelow(random: (length: number) => Uint8Array, bound: number): number {
  const range = BigInt(bound);
  const zone = U64_MAX - (U64_MAX % range);
  for (;;) {
    const value = bytesToBigInt(random(8));
    if (value < zone) return Number(value % range);
  }
}

/** Issues ring address `index`, the next free one by default, the caller persists the returned state. */
export async function issueRingAddress(
  input: Readonly<{
    state: AnonymousRingState;
    keys: RingKeys;
    index?: number;
    pairing?: Pairing;
  }>,
  context?: RequestContext,
): Promise<Readonly<{ state: AnonymousRingState; address: RingAddress }>> {
  const { state, keys } = input;
  const index = input.index ?? (state.issued.at(-1)?.index ?? -1) + 1;
  const pairing = input.pairing ?? Pairing.any();
  const issued = state.issue(index, pairing);
  const address = await ringAddressOf({ keys, ring: state.ring, index, pairing }, context);
  return Object.freeze({ state: issued, address });
}

/** The address an issued index hands out, its viewing key the per-address one, Rust `AnonymousRingState::address`. */
export async function ringAddressOf(
  input: Readonly<{ keys: RingKeys; ring: Address; index: number; pairing: Pairing }>,
  context?: RequestContext,
): Promise<RingAddress> {
  const [key] = await input.keys.ringAddressKeys(input.ring, [input.index], context);
  if (key === undefined) throw new RingError("RING_KEYS_REQUIRED");
  const address = input.keys.address();
  return new RingAddress({
    recipient: ShieldedAddress.fromPublicKeys(
      address.signingPublicKey,
      address.nullifierPublicKey,
      key,
    ),
    ringProgramId: input.ring,
    pairing: input.pairing,
  });
}
