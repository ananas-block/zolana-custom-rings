/** The ring derivations over a wallet's viewing key, Rust `zolana_ring_keys::RingKeys`. */
import { expand } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { getAddressEncoder, type Address } from "@solana/kit";

import type { Bytes16, Bytes32, RequestContext } from "@heliuslabs/zolana";
import { concatBytes, equalBytes, u32be, u64be, viewRoot } from "@heliuslabs/zolana/internal";
import {
  NullifierKey,
  ViewingKey,
  X25519PublicKey,
  type ShieldedAddress,
  type ShieldedKeypair,
} from "@heliuslabs/zolana/keypair";
import {
  LocalShieldedKeys,
  TransactionError,
  type ShieldedKeys,
} from "@heliuslabs/zolana/transaction";

import { extended } from "../operations/workflow/extended.js";
import { checkedCounter, u32Field } from "../crypto/error.js";
import { deliveredSlotSecret } from "../crypto/ring-stream.js";

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();

const INFO_SENDER_VIEW_TAG_SECRET = "TSPP/sender_view_tag";
const INFO_SENDER_VIEW_TAG_PREFIX = "TSPP/sender_view_tag/";
/** Followed by the ring program address and the address index. */
const INFO_RING_ADDRESS_KEY_PREFIX = "TSPP/ring_address_key/";
/** Followed by the ring program address. */
const INFO_RING_CHANGE_KEY_PREFIX = "TSPP/ring_change_key/";

/** The viewing key a delivered ring output was agreed under. */
export type RingRecipientKey =
  /** One of the wallet's viewing keys, the recipient of a confidential delivered output. */
  | Readonly<{ kind: "viewing"; viewingPublicKey: X25519PublicKey }>
  /** Ring address `index` of `ring`, the recipient of an anonymous output. */
  | Readonly<{ kind: "address"; ring: Address; index: number }>;

/** The public context of one delivered ring output slot. */
export interface RingDeliveryRequest {
  readonly recipient: RingRecipientKey;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly outputIndex: number;
  readonly firstNullifier: Bytes32;
}

/** The ring derivations of a wallet's viewing key, no viewing secret leaves the holder. */
export interface RingKeys extends ShieldedKeys {
  /** The keys of ring addresses `indexes` of `ring`, one per index. */
  ringAddressKeys(
    ring: Address,
    indexes: readonly number[],
    context?: RequestContext,
  ): Promise<readonly X25519PublicKey[]>;
  /** One CRDS slot secret per request, the body key, the blinding and a first contact's pair key derive from it. */
  ringDeliverySecrets(
    requests: readonly RingDeliveryRequest[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
  /** The key the sender's change in `ring` is delivered to, the sender agrees with it from `tx_sk`. */
  ringChangeKey(ring: Address, context?: RequestContext): Promise<X25519PublicKey>;
  /** The deposit tags of the current viewing key, one per counter. */
  senderViewTags(
    counters: readonly bigint[],
    context?: RequestContext,
  ): Promise<readonly Bytes32[]>;
}

/** Every ring derivation a delivered output needs, a partial holder is no ring holder. */
export function isRingKeys(keys: ShieldedKeys): keys is RingKeys {
  const candidate: Partial<Record<keyof RingKeys, unknown>> = keys;
  return (
    typeof candidate.ringAddressKeys === "function" &&
    typeof candidate.ringDeliverySecrets === "function" &&
    typeof candidate.ringChangeKey === "function" &&
    typeof candidate.senderViewTags === "function"
  );
}

/** The proving keys of a wallet beside the ring derivations of the same address. */
export function ringWalletKeys<K extends ShieldedKeys>(keys: K, ring: RingKeys): K & RingKeys {
  if (!equalBytes(keys.address().toBytes(), ring.address().toBytes()))
    throw new TransactionError("TRANSACTION_KEYS_IDENTITY_MISMATCH");
  return extended(keys, {
    ringAddressKeys: ring.ringAddressKeys.bind(ring),
    ringDeliverySecrets: ring.ringDeliverySecrets.bind(ring),
    ringChangeKey: ring.ringChangeKey.bind(ring),
    senderViewTags: ring.senderViewTags.bind(ring),
  });
}

/** `HKDF-Expand(view_root, info, 32)`, Rust `derive_secret32`. */
function viewSecret(viewing: ViewingKey, info: Uint8Array): Uint8Array {
  const secret = viewing.secretBytes();
  const root = viewRoot(secret);
  try {
    return expand(sha256, root, info, 32);
  } finally {
    secret.fill(0);
    root.fill(0);
  }
}

function derivedKey(viewing: ViewingKey, info: Uint8Array): ViewingKey {
  const secret = viewSecret(viewing, info);
  try {
    return ViewingKey.fromBytes(secret as Bytes32);
  } finally {
    secret.fill(0);
  }
}

/** The key of ring address `index` in `ring`, the recipient key its inbox stream derives from. */
export function ringAddressKey(viewing: ViewingKey, ring: Address, index: number): ViewingKey {
  u32Field(index, "index");
  return derivedKey(
    viewing,
    concatBytes(
      encoder.encode(INFO_RING_ADDRESS_KEY_PREFIX),
      new Uint8Array(addressEncoder.encode(ring)),
      u32be(index),
    ),
  );
}

/** The key a sender's change in `ring` is delivered to, found from the sender's own spends. */
export function ringChangeKey(viewing: ViewingKey, ring: Address): ViewingKey {
  return derivedKey(
    viewing,
    concatBytes(
      encoder.encode(INFO_RING_CHANGE_KEY_PREFIX),
      new Uint8Array(addressEncoder.encode(ring)),
    ),
  );
}

/** Mirrors Rust `get_sender_view_tag`, a zero byte then 31 HKDF bytes, the spender's output at `txCount`. */
export function senderViewTag(viewing: ViewingKey, txCount: bigint | number): Bytes32 {
  const secret = viewSecret(viewing, encoder.encode(INFO_SENDER_VIEW_TAG_SECRET));
  try {
    const info = concatBytes(
      encoder.encode(INFO_SENDER_VIEW_TAG_PREFIX),
      u64be(checkedCounter(txCount, "txCount")),
    );
    const okm = expand(sha256, secret, info, 31);
    const tag = new Uint8Array(32);
    tag.set(okm, 1);
    okm.fill(0);
    return tag as Bytes32;
  } finally {
    secret.fill(0);
  }
}

export class LocalRingKeys implements RingKeys {
  readonly #keys: LocalShieldedKeys;
  /** Current first, retired after. */
  readonly #viewing: readonly ViewingKey[];

  private constructor(keys: LocalShieldedKeys, viewing: readonly ViewingKey[]) {
    this.#keys = keys;
    this.#viewing = viewing;
  }

  /** Copies the keypair's roles, the keypair stays the caller's. */
  static fromKeypair(keypair: ShieldedKeypair): LocalRingKeys {
    return new LocalRingKeys(LocalShieldedKeys.fromKeypair(keypair), [keypair.viewingKey()]);
  }

  /** `viewingKeys` lists the current key first, the caller's objects stay the caller's. */
  static fromKeys(
    input: Readonly<{
      address: ShieldedAddress;
      viewingKeys: readonly ViewingKey[];
      nullifierKey: NullifierKey;
    }>,
  ): LocalRingKeys {
    return new LocalRingKeys(
      LocalShieldedKeys.fromKeys(input),
      input.viewingKeys.map((key) => key.clone()),
    );
  }

  address(): ShieldedAddress {
    return this.#keys.address();
  }

  viewingPublicKeys(): readonly X25519PublicKey[] {
    return this.#keys.viewingPublicKeys();
  }

  decrypt(requests: Parameters<ShieldedKeys["decrypt"]>[0]): ReturnType<ShieldedKeys["decrypt"]> {
    return this.#keys.decrypt(requests);
  }

  derive(requests: Parameters<ShieldedKeys["derive"]>[0]): ReturnType<ShieldedKeys["derive"]> {
    return this.#keys.derive(requests);
  }

  transactionKeys(
    requests: Parameters<ShieldedKeys["transactionKeys"]>[0],
  ): ReturnType<ShieldedKeys["transactionKeys"]> {
    return this.#keys.transactionKeys(requests);
  }

  async ringAddressKeys(
    ring: Address,
    indexes: readonly number[],
  ): Promise<readonly X25519PublicKey[]> {
    const current = this.#current();
    return indexes.map((index) => {
      const key = ringAddressKey(current, ring, index);
      try {
        return key.publicKey();
      } finally {
        key.destroy();
      }
    });
  }

  async ringDeliverySecrets(requests: readonly RingDeliveryRequest[]): Promise<readonly Bytes32[]> {
    const secrets: Bytes32[] = [];
    try {
      for (const request of requests) secrets.push(this.ringDeliverySecret(request));
    } catch (cause) {
      for (const secret of secrets) secret.fill(0);
      throw cause;
    }
    return secrets;
  }

  async ringChangeKey(ring: Address): Promise<X25519PublicKey> {
    const key = ringChangeKey(this.#current(), ring);
    try {
      return key.publicKey();
    } finally {
      key.destroy();
    }
  }

  async senderViewTags(counters: readonly bigint[]): Promise<readonly Bytes32[]> {
    const current = this.#current();
    return counters.map((counter) => senderViewTag(current, counter));
  }

  /** The CRDS secret under the recipient key, the agreement never leaves the holder. */
  ringDeliverySecret(request: RingDeliveryRequest): Bytes32 {
    if (!(request.txViewingPublicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "txViewingPublicKey" });
    }
    const recipient =
      request.recipient.kind === "viewing"
        ? this.#viewingKey(request.recipient.viewingPublicKey).clone()
        : ringAddressKey(this.#current(), request.recipient.ring, request.recipient.index);
    let agreement: Bytes32 | undefined;
    try {
      agreement = recipient.ecdh(request.txViewingPublicKey);
      return deliveredSlotSecret({
        agreement,
        txViewingKey: request.txViewingPublicKey,
        recipientViewingKey: recipient.publicKey(),
        salt: request.salt,
        outputIndex: request.outputIndex,
        firstNullifier: request.firstNullifier,
      });
    } finally {
      agreement?.fill(0);
      recipient.destroy();
    }
  }

  destroy(): void {
    this.#keys.destroy();
    for (const key of this.#viewing) key.destroy();
  }

  #current(): ViewingKey {
    const current = this.#viewing[0];
    if (current === undefined)
      throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
    return current;
  }

  #viewingKey(publicKey: X25519PublicKey): ViewingKey {
    if (!(publicKey instanceof X25519PublicKey)) {
      throw new TransactionError("TRANSACTION_DESERIALIZE", { field: "viewingPublicKey" });
    }
    const wanted = publicKey.toBytes();
    const key = this.#viewing.find((candidate) =>
      equalBytes(candidate.publicKey().toBytes(), wanted),
    );
    if (key === undefined) throw new TransactionError("TRANSACTION_MISSING_CURRENT_VIEWING_KEY");
    return key;
  }
}
