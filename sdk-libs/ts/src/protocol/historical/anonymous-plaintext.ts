/** Scheme 1 recipient and scheme 2 sender bundle plaintexts, Rust `anonymous_plaintext`. */
import {
  addressBytes,
  decodeData,
  encodeBase58,
  encodeData,
  Reader,
  Writer,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes32 } from "@heliuslabs/zolana/interface";
import {
  ShieldedPublicKey,
  X25519PublicKey,
  type Bytes33,
  type Bytes34,
} from "@heliuslabs/zolana/keypair";
import {
  Data,
  SOL_MINT,
  TransactionError,
  transactOutputBlinding,
  Utxo,
} from "@heliuslabs/zolana/transaction";

const OWNER_LEN = 34;
const MINT_LEN = 32;
const AMOUNT_LEN = 8;
const VIEWING_KEY_LEN = 33;
const BLINDING_LEN = 32;

/** A recipient plaintext with empty data, the length of every dummy body. */
export const RECIPIENT_BODY_LEN =
  OWNER_LEN + MINT_LEN + AMOUNT_LEN + VIEWING_KEY_LEN + BLINDING_LEN + 1;

export interface AnonymousRecipientPlaintext {
  readonly committed: CommittedRecipientPlaintext;
  readonly uncommitted: UncommittedRecipientPlaintext;
}

/** Unchecked until `rebuilds` matches the output hash. */
export interface CommittedRecipientPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  readonly mint: Address;
  readonly amount: bigint;
  readonly blinding: Bytes32;
}

export interface UncommittedRecipientPlaintext {
  /** Unauthenticated, the recipient pairs with whichever key the sender writes. */
  readonly senderPublicKey: X25519PublicKey;
  readonly data: Data;
}

/** Published as a message, its change outputs carry no ciphertext. */
export interface AnonymousSenderPlaintext {
  readonly committed: CommittedSenderPlaintext;
  readonly uncommitted: UncommittedSenderPlaintext;
}

/** Unchecked until `rebuilds` matches each change hash. */
export interface CommittedSenderPlaintext {
  readonly ownerPublicKey: ShieldedPublicKey;
  /** The zero address if no SPL change. */
  readonly splMint: Address;
  readonly splAmount: bigint;
  readonly solAmount: bigint;
  readonly blindingSeed: Bytes32;
}

export interface UncommittedSenderPlaintext {
  /** One per recipient output, in output order. */
  readonly recipientViewingPublicKeys: readonly X25519PublicKey[];
  readonly splData: Data;
  readonly solData: Data;
}

export function encodeAnonymousRecipient(value: AnonymousRecipientPlaintext): Uint8Array {
  const { committed, uncommitted } = value;
  return new Writer()
    .bytes(committed.ownerPublicKey.toBytes())
    .bytes(addressBytes(committed.mint, "mint"))
    .u64(committed.amount, "amount")
    .bytes(uncommitted.senderPublicKey.toBytes())
    .bytes(committed.blinding, BLINDING_LEN, "blinding")
    .bytes(encodeData(uncommitted.data))
    .finish();
}

export function decodeAnonymousRecipient(bytes: Uint8Array): AnonymousRecipientPlaintext {
  const reader = new Reader(bytes);
  const ownerPublicKey = ownerKey(reader);
  const mint = encodeBase58(reader.bytes(MINT_LEN, "mint"));
  const amount = reader.u64("amount");
  const senderPublicKey = viewingKey(reader, "senderPublicKey");
  const blinding = reader.bytes(BLINDING_LEN, "blinding") as Bytes32;
  const data = readData(reader, "data");
  reader.done();
  return {
    committed: { ownerPublicKey, mint, amount, blinding },
    uncommitted: { senderPublicKey, data },
  };
}

/** A memo is the only record a recipient output carries. */
export function anonymousRecipientUtxo(value: AnonymousRecipientPlaintext): Utxo {
  const { committed, uncommitted } = value;
  if (uncommitted.data.ringData() !== undefined || uncommitted.data.utxoData() !== undefined)
    throw new TransactionError("TRANSACTION_OUTPUT_DATA_MISMATCH", { field: "data" });
  return new Utxo({
    owner: committed.ownerPublicKey,
    asset: committed.mint,
    amount: committed.amount,
    blinding: committed.blinding,
    data: uncommitted.data,
  });
}

export function encodeAnonymousSender(value: AnonymousSenderPlaintext): Uint8Array {
  const { committed, uncommitted } = value;
  const writer = new Writer()
    .bytes(committed.ownerPublicKey.toBytes())
    .bytes(addressBytes(committed.splMint, "splMint"))
    .u64(committed.splAmount, "splAmount")
    .u64(committed.solAmount, "solAmount")
    .u8(uncommitted.recipientViewingPublicKeys.length, "recipientViewingPublicKeys");
  for (const key of uncommitted.recipientViewingPublicKeys) writer.bytes(key.toBytes());
  return writer
    .bytes(committed.blindingSeed, BLINDING_LEN, "blindingSeed")
    .bytes(encodeData(uncommitted.splData))
    .bytes(encodeData(uncommitted.solData))
    .finish();
}

export function decodeAnonymousSender(bytes: Uint8Array): AnonymousSenderPlaintext {
  const reader = new Reader(bytes);
  const ownerPublicKey = ownerKey(reader);
  const splMint = encodeBase58(reader.bytes(MINT_LEN, "splMint"));
  const splAmount = reader.u64("splAmount");
  const solAmount = reader.u64("solAmount");
  const recipientViewingPublicKeys = Array.from(
    { length: reader.u8("recipientViewingPublicKeys") },
    () => viewingKey(reader, "recipientViewingPublicKeys"),
  );
  const blindingSeed = reader.bytes(BLINDING_LEN, "blindingSeed") as Bytes32;
  const splData = readData(reader, "splData");
  const solData = readData(reader, "solData");
  reader.done();
  return {
    committed: { ownerPublicKey, splMint, splAmount, solAmount, blindingSeed },
    uncommitted: { recipientViewingPublicKeys, splData, solData },
  };
}

/** A zero amount marks a change output absent, the SOL change at slot 1 only after an SPL change. */
export function anonymousSenderUtxos(
  value: AnonymousSenderPlaintext,
  firstNullifier: Bytes32,
): readonly Utxo[] {
  const { committed, uncommitted } = value;
  if (
    (committed.splAmount === 0n && !uncommitted.splData.isEmpty()) ||
    (committed.solAmount === 0n && !uncommitted.solData.isEmpty())
  )
    throw new TransactionError("TRANSACTION_DATA_WITHOUT_OUTPUT");
  const spl =
    committed.splAmount > 0n
      ? [
          {
            asset: committed.splMint,
            amount: committed.splAmount,
            data: uncommitted.splData,
          },
        ]
      : [];
  const sol =
    committed.solAmount > 0n
      ? [{ asset: SOL_MINT, amount: committed.solAmount, data: uncommitted.solData }]
      : [];
  return [...spl, ...sol].map(
    (change, slot) =>
      new Utxo({
        owner: committed.ownerPublicKey,
        asset: change.asset,
        amount: change.amount,
        blinding: transactOutputBlinding(firstNullifier, committed.blindingSeed, slot),
        data: ringless(change.data),
      }),
  );
}

function ownerKey(reader: Reader): ShieldedPublicKey {
  return ShieldedPublicKey.fromBytes(reader.bytes(OWNER_LEN, "ownerPublicKey") as Bytes34);
}

function viewingKey(reader: Reader, name: string): X25519PublicKey {
  return X25519PublicKey.fromBytes(reader.bytes(VIEWING_KEY_LEN, name) as Bytes33);
}

/** One `Data` field in place, its records checked by `decodeData`. */
function readData(reader: Reader, name: string): Data {
  const count = reader.u8(name);
  const field = new Writer().u8(count, name);
  for (let index = 0; index < count; index += 1) {
    field.u8(reader.u8(name), name);
    const length = reader.u16(name);
    field.u16(length, name).bytes(reader.bytes(length, name));
  }
  return decodeData(field.finish());
}

function ringless(data: Data): Data {
  if (data.ringData() !== undefined)
    throw new TransactionError("TRANSACTION_MISSING_RING_PROGRAM_ID");
  return data;
}

/** A mint the registry does not bind is `TRANSACTION_UNKNOWN_MINT`. */
