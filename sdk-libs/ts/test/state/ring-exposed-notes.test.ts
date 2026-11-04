import { beforeAll, describe, expect, it } from "vitest";

import { readFileSync } from "node:fs";

import { initializePoseidon } from "@heliuslabs/zolana";
import { ZERO_NULLIFIER_PK } from "@heliuslabs/zolana/internal";
import type { Bytes32 } from "@heliuslabs/zolana/interface";
import { ShieldedAddress, ShieldedKeypair, SigningKey } from "@heliuslabs/zolana/keypair";
import { SOL_MINT, Wallet, type WalletUtxo } from "@heliuslabs/zolana/transaction";
import { getBase58Decoder, type Address } from "@solana/kit";
import { hexToBytes, bytesToHex } from "@noble/hashes/utils.js";

import { RingNullifierKey } from "../../src/crypto/keys/ring-nullifier-key.js";
import { selectRingInputs } from "../../src/operations/payments/transfer.js";
import { AnonymousWallet } from "../../src/state/anonymous-wallet.js";
import { isZeroKeyNote, mintBalances, noteState } from "../../src/state/exposed-notes.js";
import { ViewingHistory } from "../../src/state/viewing-history.js";
import { ASSETS, RING, ScanIndexer, ScanWallet } from "../helpers/ring-scan.js";
import { TREE } from "../helpers/ring-pipeline.js";

beforeAll(initializePoseidon);

function zeroKeyed(owner: ScanWallet): ShieldedAddress {
  return ShieldedAddress.fromPublicKeys(
    owner.address.signingPublicKey,
    ZERO_NULLIFIER_PK as Bytes32,
    owner.viewingKey,
  );
}

/** A wallet holding a keyed note of `keyed` and a zero-key note of `zero`. */
async function holding(keyed: bigint, zero: bigint) {
  const indexer = new ScanIndexer();
  const alice = new ScanWallet(1);
  const bob = new ScanWallet(2);
  const history = ViewingHistory.create(bob.viewingKey, 0n).withRing(RING);
  const wallet = AnonymousWallet.create(
    new Wallet({ identity: bob.address, registry: ASSETS }),
    history,
  );
  await alice.pay(indexer, [{ to: bob.address, amount: keyed }]);
  await alice.pay(indexer, [{ to: zeroKeyed(bob), amount: zero }]);
  await wallet.absorb(await bob.sync(indexer, wallet.history()));
  return { wallet, bob };
}

const select = (wallet: Wallet, amount: bigint, spendExposed?: boolean) =>
  selectRingInputs({
    wallet,
    ringProgramId: RING,
    asset: SOL_MINT,
    amount,
    inputs: "ring",
    tree: TREE,
    maxInputs: 8,
    ...(spendExposed === undefined ? {} : { spendExposed }),
  });

describe("exposed notes", () => {
  it("reports a zero-key note apart from the spendable balance", async () => {
    const { wallet } = await holding(40n, 25n);
    const [keyed, zero] = wallet.notes();
    if (keyed === undefined || zero === undefined) throw new Error("two notes");
    expect(isZeroKeyNote(keyed)).toBe(false);
    expect(isZeroKeyNote(zero)).toBe(true);
    expect(wallet.noteState(keyed)).toBe("spendable");
    expect(wallet.noteState(zero)).toBe("exposedIfSpent");
    expect(wallet.exposedNotes()).toEqual([zero]);
    expect(wallet.balances().get(SOL_MINT)).toEqual({ spendable: 40n, exposedIfSpent: 25n });
  });

  it("lets spent take precedence, a spent zero-key note leaves the list", async () => {
    const { wallet } = await holding(40n, 25n);
    const [keyed, zero] = wallet.notes();
    if (keyed === undefined || zero === undefined) throw new Error("two notes");
    const spent: WalletUtxo = { ...zero, spent: true };
    expect(noteState(spent)).toBe("spent");
    expect(mintBalances([keyed, spent]).get(SOL_MINT)).toEqual({
      spendable: 40n,
      exposedIfSpent: 0n,
    });
  });

  it("never selects one automatically and names the exposure on a shortfall", async () => {
    const { wallet } = await holding(40n, 25n);
    expect(select(wallet.wallet, 30n).map((note) => note.utxo.amount)).toEqual([40n]);
    expect(() => select(wallet.wallet, 50n)).toThrow(
      expect.objectContaining({
        code: "RING_UNFUNDED_PAST_EXPOSURE",
        details: { asset: SOL_MINT, requested: "50", exposedIfSpent: "25" },
      }),
    );
  });

  it("selects one only under a spend naming the wallet", async () => {
    const { wallet } = await holding(40n, 25n);
    expect(
      select(wallet.wallet, 50n, true)
        .map((note) => note.utxo.amount)
        .sort(),
    ).toEqual([25n, 40n]);
  });

  it("reports the plain shortfall on a wallet with no exposed funds", async () => {
    const { wallet } = await holding(40n, 25n);
    expect(() => select(wallet.wallet, 500n, true)).toThrow(
      expect.objectContaining({ code: "RING_INSUFFICIENT_BALANCE" }),
    );
  });
});

describe("list_salt.json", () => {
  const vector = JSON.parse(
    readFileSync(
      new URL("../../../../test-vectors/registry/list_salt.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, string>;

  it("derives the ring key, list salt and tag of the shared vector", async () => {
    const holder = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(hexToBytes(vector["signing_secret"] ?? "") as Bytes32),
    );
    const program = getBase58Decoder().decode(
      hexToBytes(vector["ring_program_id"] ?? ""),
    ) as Address;
    const key = await RingNullifierKey.derive(holder, program);
    const secret = key.nullifierKey();
    expect(bytesToHex(Uint8Array.of(0, ...secret.secretBytes()))).toBe(vector["nullifier_secret"]);
    secret.destroy();
    expect(bytesToHex(key.listSalt())).toBe(vector["list_salt"]);
    expect(bytesToHex(key.listTag())).toBe(vector["list_tag"]);
    const addressed = key.ringAddress(holder.shieldedAddress(), program);
    expect(addressed.recipient.nullifierPublicKey).toEqual(key.nullifierPublicKey());
    expect(addressed.recipient.nullifierPublicKey).not.toEqual(holder.nullifierPublicKey());
    expect(addressed.listSalt).toEqual(key.listSalt());
    key.destroy();
  });
});
