import { getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "@heliuslabs/zolana/interface";
import {
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
  ed25519DerivationPayload,
  isDerivationInput,
} from "@heliuslabs/zolana/keypair";
import { LocalShieldedKeys } from "@heliuslabs/zolana/transaction";

function seed(byte: number): Bytes32 {
  return new Uint8Array(32).fill(byte) as Bytes32;
}

describe("LocalShieldedKeys from a derivation seed", () => {
  it("derives the same keys from a wallet's derivation signature as from the secret", () => {
    const signing = SigningKey.fromEd25519Bytes(seed(7));
    const keypair = ShieldedKeypair.fromKeypair(signing);
    const solanaPublicKey = getAddressDecoder().decode(signing.publicKey().toBytes().subarray(1));
    const local = LocalShieldedKeys.fromKeypair(keypair);
    // The browser wallet output of signMessage(ed25519DerivationMessage(pk)).
    const derived = LocalShieldedKeys.fromDerivationSeed({
      solanaPublicKey,
      derivationSeed: signing.derivationSeed(),
    });
    expect(derived.address().ownerHash()).toEqual(local.address().ownerHash());
    expect(derived.address().viewingPublicKey.toBytes()).toEqual(
      local.address().viewingPublicKey.toBytes(),
    );
    const localViewing = local.viewingPublicKeys()[0]?.toBytes();
    expect(derived.viewingPublicKeys()[0]?.toBytes()).toEqual(localViewing);
    // The bare payload is a derivation input too, what browser wallets sign.
    expect(isDerivationInput(ed25519DerivationPayload())).toBe(true);
    // The hash-free path a page without Poseidon takes.
    expect(ViewingKey.fromDerivationSeed(signing.derivationSeed()).publicKey().toBytes()).toEqual(
      localViewing,
    );
    expect(derived.withNullifierKey((key) => key.publicKey())).toEqual(
      local.withNullifierKey((key) => key.publicKey()),
    );
  });
});
