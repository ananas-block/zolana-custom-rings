import { address, getAddressEncoder, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  ShieldedKeypair,
  ViewingKey,
  type Bytes16,
  type Bytes32,
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  type ShieldedKeys,
} from "@heliuslabs/zolana";
import { DEFAULT_TREE_ID } from "@heliuslabs/zolana/interface";
import { AssetRegistry, EncryptedScheme } from "@heliuslabs/zolana/transaction";
import { encodeOutputData } from "@heliuslabs/zolana/internal";
import {
  encodeRingDepositCapsule,
  RING_DEPOSIT_OPENING_LENGTH,
} from "../../../src/protocol/codec/deposit-capsule.js";
import { encodeRingDepositPlaintext } from "../../../src/protocol/codec/ring-deposit-plaintext.js";
import { openRingNotes } from "../../../src/state/ring-sync.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const SIGNATURE = "1".repeat(64) as Signature;

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A holder that forwards to `keys`; tests override one method to misbehave. */
function remoteOver(keys: ShieldedKeys): ShieldedKeys {
  return {
    address: () => keys.address(),
    viewingPublicKeys: () => keys.viewingPublicKeys(),
    decrypt: (requests) => keys.decrypt(requests),
    derive: (requests) => keys.derive(requests),
    transactionKeys: (requests) => keys.transactionKeys(requests),
  };
}

function ringDepositBody(
  envelope: ViewingKey,
  salt: Bytes16,
  amount: bigint,
  ciphertext: Uint8Array,
  dataHash?: Bytes32,
): Uint8Array {
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, amount, true);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, ciphertext.length, true);
  return Uint8Array.from([
    ...bytes(1),
    ...getAddressEncoder().encode(SOL_MINT),
    ...amountBytes,
    ...(dataHash === undefined ? [0] : [1, ...dataHash]),
    ...getAddressEncoder().encode(OWNER),
    ...new Uint8Array(32),
    ...envelope.publicKey().toBytes(),
    ...salt,
    ...length,
    ...ciphertext,
  ]);
}

async function openDeposit(
  input: Readonly<{ malformed?: boolean; utxoData?: Uint8Array; dataHash?: Bytes32 }> = {},
) {
  const recipient = ShieldedKeypair.generate();
  const envelope = ViewingKey.generate();
  const salt = new Uint8Array(16).fill(6) as Bytes16;
  const blinding = bytes(30);
  const utxo = new Utxo({
    owner: recipient.signingPublicKey(),
    asset: SOL_MINT,
    amount: 2_000_000_000n,
    blinding,
    data: new Data([{ kind: "ringData", bytes: new Uint8Array() }]),
    ringProgramId: OWNER,
  });
  const capsule = encodeRingDepositCapsule({
    slotIndex: 3,
    ephemeralPublicKey: ViewingKey.generate().publicKey().toBytes(),
    ciphertext: new Uint8Array(RING_DEPOSIT_OPENING_LENGTH).fill(9),
    recipientCiphertext: envelope.encryptRingDeposit(
      recipient.viewingPublicKey(),
      encodeRingDepositPlaintext({
        blinding,
        ringData: new Uint8Array(),
        ...(input.utxoData === undefined ? {} : { utxoData: input.utxoData }),
      }),
      salt,
    ),
  });
  const seen: Parameters<ShieldedKeys["decrypt"]>[0][] = [];
  const local = LocalShieldedKeys.fromKeypair(recipient);
  const holder: ShieldedKeys = {
    ...remoteOver(local),
    decrypt: (requests) => {
      seen.push(requests);
      return local.decrypt(requests);
    },
  };
  const notes = await openRingNotes({
    keys: holder,
    assets: new AssetRegistry(),
    transactions: [
      {
        slot: 3n,
        txSignature: SIGNATURE,
        outputSlots: [
          {
            viewTag: recipient.viewingPublicKey().x(),
            outputContext: {
              hash: utxo.hash(recipient.nullifierPublicKey(), DEFAULT_TREE_ID),
              tree: TREE,
              treeId: DEFAULT_TREE_ID,
              leafIndex: 9n,
            },
            payload: encodeOutputData(
              EncryptedScheme.ringDeposit,
              ringDepositBody(
                envelope,
                salt,
                utxo.amount,
                input.malformed === true ? capsule.slice(0, 12) : capsule,
                input.dataHash,
              ),
              "encrypted",
            ),
          },
        ],
        messages: [],
        nullifiers: [],
        proofless: true,
      },
    ],
  });
  return { notes, seen, utxo, capsule };
}

describe("audited ring deposit sync", () => {
  it("opens audited deposits through the ring capsule", async () => {
    const { notes, seen, utxo, capsule } = await openDeposit();
    // The holder never sees the auditor slot, only the recipient ciphertext.
    expect(seen.flat().map((request) => request.ciphertext.length)).toEqual([
      capsule.length - 42 - RING_DEPOSIT_OPENING_LENGTH,
    ]);
    expect(notes.utxos.map((entry) => entry.utxo)).toEqual([utxo]);
  });

  it("asks the holder nothing for a malformed capsule", async () => {
    const { notes, seen } = await openDeposit({ malformed: true });
    expect(notes.utxos).toEqual([]);
    expect(seen).toEqual([]);
  });

  it.each([
    ["an absent", undefined],
    ["a zero", new Uint8Array(32) as Bytes32],
  ])("refuses utxo data under %s data hash", async (_, dataHash) => {
    const { notes, seen } = await openDeposit({
      utxoData: Uint8Array.of(1, 2, 3),
      ...(dataHash === undefined ? {} : { dataHash }),
    });
    expect(seen).toHaveLength(1);
    expect(notes.utxos).toEqual([]);
  });
});
