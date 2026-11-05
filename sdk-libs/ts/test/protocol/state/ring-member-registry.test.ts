import { address } from "@solana/kit";
import { beforeAll, describe, expect, it, vi } from "vitest";

import records from "../../../../../test-vectors/registry/ring-records.json" with { type: "json" };
import { initializePoseidon } from "@heliuslabs/zolana";
import { addressBytes } from "@heliuslabs/zolana/internal";
import type { Bytes31, Bytes32 } from "@heliuslabs/zolana/interface";
import {
  NullifierKey,
  ShieldedKeypair,
  SigningKey,
  X25519Keypair,
} from "@heliuslabs/zolana/keypair";
import { MEMBER_REGISTRY_EMPTY_ROOT } from "../../../src/protocol/membership/member-opening.js";
import type { AuditCredential } from "../../../src/protocol/membership/credential.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  fetchRingSealedKey,
  openNullifierKey,
  openRingSealedKey,
  openListSalt,
  sealNullifierKey,
  sealNullifierKeyWith,
} from "../../../src/operations/management/register-key.js";
import {
  resolveCredential,
  type CredentialClient,
  type CredentialLookup,
} from "../../../src/rpc/credential-resolver.js";
import { recordTree } from "../../helpers/member-registry.js";

vi.mock("../../../src/rpc/credential-resolver.js", async (actual) => ({
  ...(await actual<typeof import("../../../src/rpc/credential-resolver.js")>()),
  resolveCredential: vi.fn(),
}));

// sdk-libs/client/src/crypto/encryption/mod.rs `the_sealed_key_matches_the_pinned_vector`.
const AUDITOR_SK = hex("01323130373635343b3a39383f3e3d3c23222120272625242b2a29282f2e2d2c");
const EPHEMERAL_SK = hex("011013121514171619181b1a1d1c1f1e010003020504070609080b0a0d0c0f0e");
const NULLIFIER_SECRET = hex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const NULLIFIER_PK = hex("2d1faf6cf358763421511eb637adf7b6609443d38edc4ed2b042dfbf834b03f5");
const EPH_PK = hex("043632fe89228ea5215eea45a56704f569e3929868a8573363d015e39609f0eb63");
const CIPHERTEXT = hex(
  "4be6ab2544799bd0c018ff495f59e8205d6fe9d007f74e44ec739529c0b27f25d23f6f5b30bde013afd5a02f1913cb4c354c8529e12a01ad583bb6f72692d99c",
);

const LIST_SALT = Uint8Array.of(0, ...new Uint8Array(31).fill(9)) as Bytes32;
const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const CLIENT = {} as CredentialClient;
const AUDITOR = X25519Keypair.fromBytes(AUDITOR_SK);

beforeAll(initializePoseidon);

function hex(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value, "hex"));
}

function actor(seed: number) {
  const keypair = ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
  const shielded = keypair.shieldedAddress();
  const signer = shielded.solanaAddress();
  return { keypair, shielded, signer, member: memberOfTag(addressBytes(signer)) };
}

function enrolled(seed: number) {
  const who = actor(seed);
  const envelope = sealNullifierKey(who.keypair.nullifierKey(), LIST_SALT, AUDITOR.publicKey());
  envelope.ephemeralSecret.fill(0);
  const credential: AuditCredential = {
    ringId: new Uint8Array(32).fill(1) as Bytes32,
    member: who.member,
    nullifierPk: envelope.nullifierPublicKey,
    listTag: new Uint8Array(32).fill(3) as Bytes32,
    auditorPubkey: AUDITOR.publicKey().toBytes(),
    ephU: envelope.sealed.ephemeralPublicKey.u(),
    ciphertext: envelope.sealed.ciphertext,
  };
  const present = { kind: "present", credential } as unknown as CredentialLookup;
  return { ...who, credential, present };
}

describe("nullifier key envelope", () => {
  it("matches the Rust vector and opens only for the auditor", () => {
    const ephemeral = X25519Keypair.fromBytes(EPHEMERAL_SK);
    const nullifierKey = NullifierKey.fromSecret(NULLIFIER_SECRET as Bytes31);
    const envelope = sealNullifierKeyWith(ephemeral, nullifierKey, LIST_SALT, AUDITOR.publicKey());
    expect(envelope.nullifierPublicKey).toEqual(NULLIFIER_PK);
    expect(envelope.sealed.ephemeralPublicKey.toBytes()).toEqual(EPH_PK);
    expect(envelope.sealed.ciphertext).toEqual(CIPHERTEXT);
    expect(openNullifierKey(envelope.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
    expect(openListSalt(envelope.sealed, AUDITOR)).toEqual(LIST_SALT);
    const fresh = sealNullifierKey(nullifierKey, LIST_SALT, AUDITOR.publicKey());
    expect(fresh.sealed.ciphertext).not.toEqual(CIPHERTEXT);
    expect(openNullifierKey(fresh.sealed, AUDITOR).secretBytes()).toEqual(NULLIFIER_SECRET);
  });

  it("pins the sentinel-only root the registry starts from", () => {
    expect(Buffer.from(MEMBER_REGISTRY_EMPTY_ROOT).toString("hex")).toBe(records.empty_root);
    expect(recordTree().root).toEqual(MEMBER_REGISTRY_EMPTY_ROOT);
  });
});

describe("enrolled keys", () => {
  it("opens an enrolled owner's key for the auditor only", async () => {
    const who = enrolled(11);
    vi.mocked(resolveCredential).mockResolvedValue(who.present);
    const entry = await fetchRingSealedKey({
      client: CLIENT,
      ringProgramId: RING,
      owner: who.signer,
    });
    expect(resolveCredential).toHaveBeenCalledWith(
      { client: CLIENT, ring: RING, owner: who.signer },
      undefined,
    );
    expect(entry.credential).toBe(who.present);
    expect(entry.sealed.owner).toBe(who.signer);
    expect(entry.sealed.ciphertext).toEqual(who.credential.ciphertext);
    expect(entry.sealed.nullifierPk).toEqual(who.credential.nullifierPk);
    expect(openRingSealedKey(entry, AUDITOR).secretBytes()).toEqual(
      who.keypair.nullifierKey().secretBytes(),
    );
    expect(() => openRingSealedKey(entry, X25519Keypair.generate())).toThrow(
      expect.objectContaining({ code: "RING_KEY_ENVELOPE_INVALID" }),
    );
  });

  it("refuses a key the credential does not bind", async () => {
    const who = enrolled(12);
    const other = enrolled(14);
    vi.mocked(resolveCredential).mockResolvedValue({
      ...who.present,
      credential: { ...who.credential, nullifierPk: other.credential.nullifierPk },
    } as CredentialLookup);
    const entry = await fetchRingSealedKey({
      client: CLIENT,
      ringProgramId: RING,
      owner: who.signer,
    });
    expect(() => openRingSealedKey(entry, AUDITOR)).toThrow(
      expect.objectContaining({ code: "RING_KEY_ENVELOPE_INVALID" }),
    );
  });

  it("refuses an owner proven absent", async () => {
    vi.mocked(resolveCredential).mockResolvedValue({ kind: "absent" } as CredentialLookup);
    await expect(
      fetchRingSealedKey({ client: CLIENT, ringProgramId: RING, owner: actor(13).signer }),
    ).rejects.toMatchObject({ code: "RING_KEY_NOT_REGISTERED" });
  });

  it("refuses an unknown lookup rather than read it as absent", async () => {
    vi.mocked(resolveCredential).mockResolvedValue({ kind: "unknown", reason: "queued" });
    await expect(
      fetchRingSealedKey({ client: CLIENT, ringProgramId: RING, owner: actor(13).signer }),
    ).rejects.toMatchObject({ code: "RING_CREDENTIAL_UNKNOWN", details: { reason: "queued" } });
  });
});
