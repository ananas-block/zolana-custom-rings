import { address, getAddressEncoder, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";
import {
  ShieldedKeypair,
  ViewingKey,
  type Bytes16,
  type Bytes32,
  type Bytes96,
  Data,
  LocalShieldedKeys,
  SOL_MINT,
  Utxo,
  Wallet,
  serializeWallet,
  type ShieldedKeys,
} from "@heliuslabs/zolana";
import { DEFAULT_TREE_ID } from "@heliuslabs/zolana/interface";
import { decryptTransactions, EncryptedScheme } from "@heliuslabs/zolana/transaction";
import { encodeOutputData, encodeRingDepositPlaintext } from "@heliuslabs/zolana/internal";
import { encodeRingDepositCapsule } from "../src/ring/deposit-capsule.js";
import { customRingDepositPayload } from "../src/ring/deposit-payload.js";

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

function decryptWithKeys(
  keys: ShieldedKeys,
  input: Omit<Parameters<typeof decryptTransactions>[0], "keys">,
): Promise<ReturnType<typeof decryptTransactions> extends Promise<infer R> ? R : never> {
  return decryptTransactions({ ...input, keys });
}

function ringDepositBody(
  envelope: ViewingKey,
  salt: Bytes16,
  amount: bigint,
  ciphertext: Uint8Array,
): Uint8Array {
  const amountBytes = new Uint8Array(8);
  new DataView(amountBytes.buffer).setBigUint64(0, amount, true);
  const length = new Uint8Array(4);
  new DataView(length.buffer).setUint32(0, ciphertext.length, true);
  return Uint8Array.from([
    ...bytes(1),
    ...getAddressEncoder().encode(SOL_MINT),
    ...amountBytes,
    0,
    ...getAddressEncoder().encode(OWNER),
    ...new Uint8Array(32),
    ...envelope.publicKey().toBytes(),
    ...salt,
    ...length,
    ...ciphertext,
  ]);
}

describe("audited ring deposit sync", () => {
  it.each([false, true])(
    "opens audited deposits through customRingDepositPayload, malformed %s",
    async (malformed) => {
      const recipient = ShieldedKeypair.generate();
      const wallet = new Wallet({ identity: recipient.shieldedAddress() });
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
        ciphertext: new Uint8Array(96).fill(9) as Bytes96,
        recipientCiphertext: envelope.encryptRingDeposit(
          recipient.viewingPublicKey(),
          encodeRingDepositPlaintext({ blinding, ringData: new Uint8Array() }),
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

      const before = serializeWallet(wallet);
      const pending = decryptWithKeys(holder, {
        wallet,
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
                  leafIndex: 9n,
                },
                payload: encodeOutputData(
                  EncryptedScheme.ringDeposit,
                  ringDepositBody(
                    envelope,
                    salt,
                    utxo.amount,
                    malformed ? capsule.slice(0, 12) : capsule,
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
        config: { depositPayloadDecoder: customRingDepositPayload },
      });

      if (malformed) {
        await expect(pending).rejects.toMatchObject({ code: "INTERFACE_CODEC" });
        expect(serializeWallet(wallet)).toEqual(before);
        expect(seen).toEqual([]);
        return;
      }
      const report = await pending;
      expect(report).toMatchObject({ storedUtxos: 1, undecryptableCandidates: 0 });
      // The holder never sees the auditor slot, only the recipient ciphertext.
      expect(seen.flat().map((request) => request.ciphertext.length)).toEqual([
        capsule.length - 138,
      ]);
      expect(wallet.utxos()[0]?.utxo).toEqual(utxo);
    },
  );
});
