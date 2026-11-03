import { describe, expect, it } from "vitest";

import bodies from "../../../../../test-vectors/audit/anonymous_bodies.json" with { type: "json" };
import signerSet from "../../../../../test-vectors/audit/signer_set.json" with { type: "json" };
import statements from "../../../../../test-vectors/audit/transfer_statement_v3.json" with { type: "json" };
import debits from "../../../../../test-vectors/policy/debit.json" with { type: "json" };
import pools from "../../../../../test-vectors/policy/pool_capacity.json" with { type: "json" };
import zeroNullifier from "../../../../../test-vectors/registry/zero_nullifier.json" with { type: "json" };
import {
  ZERO_32,
  ZERO_NULLIFIER_PK,
  bigIntBytes,
  bytesToBigInt,
  encodeBase58,
} from "@heliuslabs/zolana/internal";
import type { Bytes16, Bytes31, Bytes32, Bytes33 } from "@heliuslabs/zolana/interface";
import {
  ViewingKey,
  X25519Keypair,
  poseidon,
  NullifierKey,
  ShieldedAddress,
  ShieldedKeypair,
} from "@heliuslabs/zolana/keypair";
import { Data } from "@heliuslabs/zolana/transaction";

import { RingDomain } from "../../../src/crypto/derivation/ring-domain.js";
import {
  bundleTag,
  deliveredSlotSecret,
  txKeySlotSecret,
} from "../../../src/crypto/derivation/ring-stream.js";
import { anonymousSlotTag } from "../../../src/operations/payments/output-rail.js";
import { x25519FromU } from "../../../src/crypto/keys/x25519.js";
import {
  MIN_REPLY_LEN,
  openRecipientBody,
  openReply,
  openSenderBundle,
  sealRecipientBody,
  sealReply,
  sealSenderBundle,
} from "../../../src/protocol/codec/anonymous-delivery.js";
import { ownerDebits } from "../../../src/protocol/membership/owner-debits.js";
import {
  ciphertextDigest,
  recipientTagChain,
  signerBinding,
  transferStatementElements,
  transferStatementHash,
  type TransferFamily,
  type TransferStatement,
} from "../../../src/protocol/proof/statement.js";
import {
  screenedOwners,
  signerSlots,
  transferCircuitType,
  transferInputClass,
  transferKeys,
  transferPoolCapacity,
} from "../../../src/protocol/proof/transfer-shapes.js";
import type { RingOutput } from "../../../src/protocol/transaction/transact.js";
import { LocalRingKeys, type RingTagProbe } from "../../../src/state/ring-keys.js";

function bytes<T extends Uint8Array>(value: string, length: number): T {
  const decoded = Uint8Array.from(Buffer.from(value, "hex"));
  if (decoded.length !== length) throw new RangeError(`expected ${String(length)} bytes`);
  return decoded as T;
}

function field(value: string): Bytes32 {
  return bytes<Bytes32>(value, 32);
}

function hex(value: Uint8Array): string {
  return Buffer.from(value).toString("hex");
}

describe("transfer_statement_v3.json", () => {
  interface StatementVector {
    readonly name: string;
    readonly family: string;
    readonly in_proof: boolean;
    readonly delegate: boolean;
    readonly exempt: boolean;
    readonly approval_required: boolean;
    readonly first_nullifier: string;
    readonly ring_id: string;
    readonly tx_viewing_u: string;
    readonly auditor_pubkey: string;
    readonly eph_u: string;
    readonly envelope: string;
    readonly salt: string;
    readonly layout: number;
    readonly output_capacity: number;
    readonly output_count: number;
    readonly outputs: readonly Readonly<{
      kind: string;
      hash: string;
      u?: string;
      body?: string;
      record?: string;
      recipient_body?: string | null;
      tag?: string;
    }>[];
    readonly input_count: number;
    readonly sender_bundle?: string | null;
    readonly sender_bundle_tag?: string | null;
    readonly replies?: string | null;
    readonly private_tx_hash: string;
    readonly sender?: string;
    readonly recipients?: readonly string[];
    readonly party_identities?: readonly string[];
    readonly signer_slots: number;
    readonly signer_count: number;
    readonly signer_chain: string;
    readonly signers?: readonly string[];
    readonly policy_hash: string;
    readonly own_root: string;
    readonly curator_root: string;
    readonly public_assets: readonly string[];
    readonly public_amounts: readonly string[];
    readonly public_gross: readonly string[];
    readonly withdrawal_hash: string;
    readonly elements: readonly string[];
    readonly public_input_hash: string;
  }
  type StatementCase = (typeof statements.cases)[number];
  const statementCases = statements.cases as unknown as readonly StatementVector[];

  const raw = (value: string): Uint8Array => Uint8Array.from(Buffer.from(value, "hex"));

  function statementOf(vector: StatementVector): TransferStatement {
    const outputs = vector.outputs.map((output): RingOutput => {
      const hash = field(output.hash);
      if (output.kind === "exit")
        return { kind: "exit", hash, ownerTag: ZERO_32, payload: new Uint8Array() };
      if (output.kind === "delivered")
        return { kind: "delivered", hash, u: field(output.u ?? ""), body: raw(output.body ?? "") };
      return output.recipient_body === null || output.recipient_body === undefined
        ? { kind: "change", hash, tag: ZERO_32 }
        : {
            kind: "anonymous",
            hash,
            tag: field(output.tag ?? ""),
            body: raw(output.recipient_body),
          };
    });
    const family: TransferFamily =
      vector.family === "anonymous"
        ? {
            kind: "anonymous",
            partyIdentities: (vector.party_identities ?? []).map(field) as unknown as [
              Bytes32,
              Bytes32,
              Bytes32,
            ],
            senderBundle: raw(vector.sender_bundle ?? ""),
            senderBundleTag: field(vector.sender_bundle_tag ?? ""),
            ...(vector.replies === null || vector.replies === undefined || vector.replies === ""
              ? {}
              : { replies: raw(vector.replies) }),
          }
        : {
            kind: "confidential",
            inProof: vector.in_proof,
            delegate: vector.delegate,
            sender: field(vector.sender ?? ""),
            recipients: (vector.recipients ?? []).map(field),
          };
    return {
      head: {
        firstNullifier: field(vector.first_nullifier),
        ringId: field(vector.ring_id),
        txViewingU: field(vector.tx_viewing_u),
        auditorPubkey: bytes<Bytes33>(vector.auditor_pubkey, 33),
        ephU: field(vector.eph_u),
        envelope: raw(vector.envelope),
        salt: bytes<Bytes16>(vector.salt, 16),
        layout: {
          keyEscrow: (vector.layout & 2) !== 0,
          fullOpenings: (vector.layout & 8) !== 0,
        },
      },
      family,
      exempt: vector.exempt,
      approvalRequired: vector.approval_required,
      capacity: vector.output_capacity,
      outputs,
      outputCiphertexts: vector.outputs.map((output) =>
        raw(output.kind === "delivered" ? (output.body ?? "") : (output.record ?? "")),
      ),
      // The vector's signers are owner identities, the chain rebuilds from them as they stand.
      signers: signerBinding((vector.signers ?? []).map(field), vector.signer_slots),
      inputCount: vector.input_count,
      privateTxHash: field(vector.private_tx_hash),
      roots: {
        policyHash: field(vector.policy_hash),
        ownRoot: field(vector.own_root),
        curatorRoot: field(vector.curator_root),
      },
      publicAssets: vector.public_assets.map(field),
      publicAmounts: vector.public_amounts.map(field),
      publicGross: vector.public_gross.map(field),
      withdrawalHash: field(vector.withdrawal_hash),
    };
  }

  it.each(statementCases.map((vector) => [vector.name, vector] as const))(
    "reaches the public input hash of %s from its preimages",
    (_, vector) => {
      expect(vector.elements).toHaveLength(
        vector.family === "anonymous" ? 45 : 41 + vector.output_capacity,
      );
      const statement = statementOf(vector);
      expect(hex(statement.signers.chain)).toBe(vector.signer_chain);
      expect(transferStatementElements(statement).map(hex)).toEqual(vector.elements);
      expect(hex(transferStatementHash(statement))).toBe(vector.public_input_hash);
    },
  );

  it("reads a tag on every recipient and dummy slot and a zero cell on change and exit through the real chain", () => {
    for (const vector of statementCases.filter((row) => row.family === "anonymous")) {
      const statement = statementOf(vector);
      const elements = transferStatementElements(statement);
      const cells = vector.outputs.map((output) => output.tag ?? "00".repeat(32));
      expect(
        statement.outputs.map((output) => hex(output.kind === "anonymous" ? output.tag : ZERO_32)),
        vector.name,
      ).toEqual(cells);
      expect(hex(elements[18] ?? ZERO_32), vector.name).toBe(
        hex(
          recipientTagChain(
            statement.outputs,
            vector.output_capacity,
            field(vector.sender_bundle_tag ?? ""),
          ),
        ),
      );
    }
  });

  it("binds chain zero at a signer count of zero on every rail and one chain per run", () => {
    const signerRow = (vector: StatementCase) =>
      vector.family === "anonymous" ? [27, 28] : [24, 25];
    for (const vector of statements.cases) {
      const [count, chain] = signerRow(vector).map((index) => vector.elements[index] ?? "");
      expect(BigInt(`0x${count}`), vector.name).toBe(BigInt(vector.signer_count));
      if (vector.signer_count === 0) expect(chain, vector.name).toBe(hex(ZERO_32));
      else expect(chain, vector.name).not.toBe(hex(ZERO_32));
    }
    const coOwned = statements.cases.find((vector) => vector.name === "commitment_co_owner");
    const oneOwner = signerSet.cases.find((vector) => vector.name === "one owner");
    expect(coOwned?.elements[28]).toBe(oneOwner?.signer_chain);
  });
});

describe("signer_set.json", () => {
  it.each(signerSet.cases.map((vector) => [vector.name, vector] as const))(
    "chains %s",
    (_, vector) => {
      const binding = signerBinding(vector.signers.map(field), vector.slots);
      expect(binding.count).toBe(vector.signers.length);
      expect(hex(binding.chain)).toBe(vector.signer_chain);
    },
  );

  it("refuses a run past the key's slots", () => {
    expect(() => signerBinding([field(signerSet.cases[2]?.signers[0] ?? "")], 0)).toThrow(
      expect.objectContaining({ code: "RING_INVALID_LENGTH" }),
    );
  });
});

describe("anonymous_bodies.json", () => {
  it("reads the published tags through the holder under each reader's own key", async () => {
    const holderOf = (secret: string): LocalRingKeys => {
      const viewing = ViewingKey.fromBytes(field(secret));
      const nullifierKey = NullifierKey.fromSecret(new Uint8Array(31).fill(7) as Bytes31);
      return LocalRingKeys.fromKeys({
        address: ShieldedAddress.fromPublicKeys(
          ShieldedKeypair.generate().signingPublicKey(),
          nullifierKey.publicKey(),
          viewing.publicKey(),
        ),
        viewingKeys: [viewing],
        nullifierKey,
      });
    };
    const txViewing = X25519Keypair.fromBytes(field(bodies.tx_viewing_sk));
    const frame = (holder: LocalRingKeys, probes: readonly RingTagProbe[]) => ({
      viewingPublicKey: holder.address().viewingPublicKey,
      txViewingPublicKey: txViewing.publicKey(),
      salt: bytes<Bytes16>(bodies.salt, 16),
      firstNullifier: field(bodies.first_nullifier),
      probes,
    });
    const recipient = holderOf(bodies.recipient_viewing_sk);
    const [recipientMatches] = await recipient.ringTagMatches([
      frame(recipient, [
        { kind: "recipient", outputIndex: bodies.body_index, tag: field(bodies.body_tag) },
        { kind: "recipient", outputIndex: bodies.body_index, tag: field(bodies.dummy_tag) },
      ]),
    ]);
    expect(recipientMatches?.map((secret) => secret && hex(secret))).toEqual([
      bodies.body_slot_secret,
      undefined,
    ]);
    const sender = holderOf(bodies.sender_viewing_sk);
    const [senderMatches] = await sender.ringTagMatches([
      frame(sender, [
        { kind: "senderBundle", outputIndex: bodies.output_count, tag: field(bodies.bundle_tag) },
      ]),
    ]);
    expect(senderMatches?.map((secret) => secret && hex(secret))).toEqual([
      bodies.bundle_slot_secret,
    ]);
  });

  const body = {
    blinding: field(bodies.body_blinding),
    amount: BigInt(bodies.body_amount),
    mint: encodeBase58(field(bodies.body_mint)),
  };
  const bundle = {
    mint: encodeBase58(field(bodies.change_mint)),
    amount: BigInt(bodies.change_amount),
    solAmount: 0n,
    outputSeed: field(bodies.output_seed),
    recipientKeys: bodies.recipient_keys.map((key) => (key === "" ? ZERO_32 : field(key))),
  };

  it("rebuilds both CRDS slot secrets, the bundle's at index m", () => {
    const txViewing = X25519Keypair.fromBytes(field(bodies.tx_viewing_sk));
    const secret = (u: string, outputIndex: number): string => {
      const recipientViewingKey = x25519FromU(field(u));
      return hex(
        deliveredSlotSecret({
          agreement: txViewing.ecdh(recipientViewingKey),
          txViewingKey: txViewing.publicKey(),
          recipientViewingKey,
          salt: bytes<Bytes16>(bodies.salt, 16),
          outputIndex,
          firstNullifier: field(bodies.first_nullifier),
        }),
      );
    };
    const recipient = bodies.recipient_keys[bodies.body_index] ?? "";
    expect(secret(recipient, bodies.body_index)).toBe(bodies.body_slot_secret);
    expect(secret(bodies.sender_viewing_key, bodies.output_count)).toBe(bodies.bundle_slot_secret);
    txViewing.destroy();
  });

  it("derives every published tag through the rail's own functions", () => {
    expect(bodies.recipient_tag_domain).toBe(RingDomain.recipientTagDomain.toString(16));
    expect(bodies.sender_tag_domain).toBe(RingDomain.senderTagDomain.toString(16));
    const txViewingKey = ViewingKey.fromBytes(field(bodies.tx_viewing_sk));
    const slotSecret = (u: string, outputIndex: number): Bytes32 =>
      txKeySlotSecret({
        txViewingKey,
        recipientViewingKey: x25519FromU(field(u)),
        salt: bytes<Bytes16>(bodies.salt, 16),
        outputIndex,
        firstNullifier: field(bodies.first_nullifier),
      });
    const recipient = x25519FromU(field(bodies.recipient_keys[bodies.body_index] ?? ""));
    const unreached = (): Bytes32 => {
      throw new Error("no slot secret on this slot");
    };
    const payment = anonymousSlotTag(
      { kind: "payment", payment: { recipient, reply: null } },
      (key) => slotSecret(hex(key.u()), bodies.body_index),
    );
    expect(hex(payment ?? ZERO_32)).toBe(bodies.body_tag);
    const dummy = anonymousSlotTag(
      { kind: "dummy", preimage: field(bodies.dummy_tag_preimage) },
      unreached,
    );
    expect(hex(dummy ?? ZERO_32)).toBe(bodies.dummy_tag);
    expect(anonymousSlotTag({ kind: "change" }, unreached)).toEqual(ZERO_32);
    expect(anonymousSlotTag({ kind: "exit" }, unreached)).toBeUndefined();
    expect(hex(bundleTag(slotSecret(bodies.sender_viewing_key, bodies.output_count)))).toBe(
      bodies.bundle_tag,
    );
    txViewingKey.destroy();
  });

  it("seals and opens the scheme 11 body", () => {
    const secret = field(bodies.body_slot_secret);
    expect(hex(sealRecipientBody(secret, body))).toBe(bodies.body);
    expect(openRecipientBody(secret, bytes(bodies.body, 72))).toEqual(body);
  });

  it("seals and opens the scheme 12 bundle and hashes its digest", () => {
    const secret = field(bodies.bundle_slot_secret);
    const sealed = bytes(bodies.bundle, 80 + 32 * bodies.output_count);
    expect(hex(sealSenderBundle(secret, bundle))).toBe(bodies.bundle);
    expect(openSenderBundle(secret, sealed, bodies.output_count)).toEqual(bundle);
    expect(hex(ciphertextDigest(sealed))).toBe(bodies.bundle_digest);
  });

  it("opens a reply under the body's secret on a stream apart from the body's", () => {
    const secret = field(bodies.body_slot_secret);
    const viewingKey = x25519FromU(field(bodies.sender_viewing_key));
    const reply = {
      viewingKey,
      ownerKey: new Uint8Array(32).fill(1) as Bytes32,
      nullifierPk: new Uint8Array(32).fill(2) as Bytes32,
      data: new Data(),
    };
    const sealed = sealReply(secret, reply, MIN_REPLY_LEN);
    expect(hex(sealed.subarray(0, 72))).not.toBe(bodies.body);
    const opened = openReply(secret, sealed);
    expect(opened?.viewingKey.u()).toEqual(viewingKey.u());
    expect(opened?.ownerKey).toEqual(reply.ownerKey);
    expect(opened?.nullifierPk).toEqual(reply.nullifierPk);
  });
});

describe("debit.json", () => {
  const identity = (value: number): Bytes32 => bigIntBytes(BigInt(value), 32) as Bytes32;
  const slot = (row: Readonly<{ owner: number; asset: number; amount: number }>) => ({
    owner: identity(row.owner),
    asset: identity(row.asset),
    amount: BigInt(row.amount),
  });

  it.each(debits.cases.map((vector) => [vector.name, vector] as const))(
    "debits %s, a zero row absent",
    (_, vector) => {
      const rows = ownerDebits({
        senders: vector.debits.map((row) => identity(row.owner)),
        assets: vector.debits.map((row) => identity(row.asset)),
        inputs: vector.inputs.map(slot),
        outputs: vector.outputs.map((output) => ({ ...slot(output), ring: output.ring })),
      });
      expect(
        rows.map((row) => [bytesToBigInt(row.owner), bytesToBigInt(row.asset), row.debit]),
      ).toEqual(
        vector.debits
          .filter((row) => row.debit > 0)
          .map((row) => [BigInt(row.owner), BigInt(row.asset), BigInt(row.debit)]),
      );
    },
  );
});

describe("pool_capacity.json", () => {
  it("names every key in catalog order at its pool widths, Q and S", () => {
    const keys = transferKeys();
    expect(keys.map((key) => transferCircuitType(key).replaceAll("-", "_"))).toEqual(
      pools.keys.map((key) => key.key),
    );
    keys.forEach((key, index) => {
      const vector = pools.keys[index];
      expect(transferPoolCapacity(key)).toEqual({ own: vector?.own, curator: vector?.curator });
      const assets = Math.max(Math.min(key.withdrawals, 3), 3);
      expect(screenedOwners(key)).toBe(
        (vector?.own ?? 0) - 2 * key.outputs - key.withdrawals - assets,
      );
      expect(signerSlots(key)).toBe(
        key.family === "transferAnonymousEntry" ? 0 : transferInputClass(key),
      );
    });
  });
});

describe("zero_nullifier.json", () => {
  it("names the key of nullifier secret zero", () => {
    expect(hex(ZERO_NULLIFIER_PK)).toBe(zeroNullifier.nullifier_pk);
    expect(hex(poseidon([ZERO_32]))).toBe(zeroNullifier.nullifier_pk);
  });
});
