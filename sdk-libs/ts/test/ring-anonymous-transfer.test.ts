import { policyWithdrawalHash } from "../src/ring/withdrawals.js";
import { AccountState, getTokenEncoder } from "@solana-program/token";
import {
  AccountRole,
  address,
  decompileTransactionMessage,
  getCompiledTransactionMessageDecoder,
  none,
  some,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ClientError } from "@heliuslabs/zolana/client";
import type { WalletKeys, RpcAccount } from "@heliuslabs/zolana/client";
import {
  DEFAULT_INDEXER_POLL_CONFIG,
  ZolanaApi,
  ZolanaIndexer,
  poseidon,
  SYSTEM_PROGRAM,
  addressBytes,
  associatedTokenAddress,
  splInterfaceWithBump,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import { initializePoseidon } from "@heliuslabs/zolana";
import {
  SOL_INTERFACE,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  treeIdField,
  TRANSACTION_SIZE_LIMIT,
  transactionSize,
  TransactWithdrawal,
  type Bytes32,
} from "@heliuslabs/zolana/interface";
import {
  randomBlinding,
  ShieldedKeypair,
  SigningKey,
  X25519PublicKey,
} from "@heliuslabs/zolana/keypair";
import {
  AssetRegistry,
  SOL_MINT,
  ConfidentialTransfer,
  WithdrawalTarget,
  type SettlementTransfer,
  decodeConfidential,
  ProofInputUtxo,
  Utxo,
  Wallet,
  type SppProofInputs,
} from "@heliuslabs/zolana/transaction";
import { approveRingUnattended, type RingApprovalRequest } from "../src/transaction/intent.js";
import { ringProofCircuit } from "../src/client/prover/ring.js";
import { ringMemberRegistryAddress } from "../src/interface/pda/index.js";
import { ringCircuitType } from "../src/interface/proving-keys.js";
import { Pairing, type RingAddress } from "../src/keypair/ring-address.js";
import {
  EPOCH_SLOTS,
  J_INBOX,
  inboxKey,
  inboxTag,
  pairKey,
  pairTag,
  ringIdField,
  senderCommitment,
  tagEpoch,
  tagIndex,
} from "../src/keypair/ring-stream.js";
import {
  ANCHOR_DECOYS,
  anonymousExitTokenOwner,
  checkAnonymousSlots,
  signingKeySpendSigner,
  type AnonymousSpendSigner,
} from "../src/ring/anonymous.js";
import { RING_COSIGN_TRANSFERS, decodeRingMemberRegistry } from "../src/ring/codecs.js";
import { ListId, buildRuleTable, memberOfAsset, memberOfIdentity } from "../src/ring/policy.js";
import { policyStatementHash } from "../src/ring/statement.js";
import type { ProvenRingTransfer } from "../src/ring/pipeline.js";
import { CustomRingTransfer, type AnonymousTransfer } from "../src/ring/rails.js";
import {
  buildRingTransferTransaction,
  buildRingWithdrawalTransaction,
} from "../src/ring/transfer.js";
import { RingTransactData } from "../src/ring/transact.js";

import { BLOCKHASH } from "../../../zolana/sdk-libs/ts/test/helpers/clients.js";

import {
  ANCHOR_ROOT_INDEX,
  TREE,
  anchorTreeAccount,
  TREE_ID,
  checkAccounts,
  checkAudit,
  checkDisclosure,
  checkFrameCounted,
  checkRingBlindings,
  expanded,
  itemAt,
  noteInput,
  openDelivered,
  randomAddress,
  ringError,
  ringFixture,
  small,
  walletKeys,
  type Fixture,
  type RingFixtureOptions,
} from "./helpers/ring-pipeline.js";
import { publicAmountFields, publicSlots } from "../src/interface/spp.js";
import { TREE_STATE_PAUSED } from "../src/interface/codecs.js";
import { type RingKeys } from "../src/transaction/wallet/ring-keys.js";
import {
  AnonymousRingState,
  type SentFirstContact,
} from "../src/transaction/wallet/anonymous-state.js";
import { ringAddressOf } from "../src/wallet/anonymous.js";

await initializePoseidon();

const assets = new AssetRegistry();
/** The fixture lands every transfer at slot 1. */
const EPOCH = tagEpoch(1n);

interface Sender {
  readonly signing: SigningKey;
  readonly keypair: ShieldedKeypair;
}

function anonymousSender(): Sender {
  const signing = SigningKey.generate();
  return { signing, keypair: ShieldedKeypair.fromKeypair(signing) };
}

function anonymousRing(options: RingFixtureOptions = {}): Promise<Fixture> {
  return ringFixture({ mode: "anonymous", ...options });
}

/** One note of the sender, of the ring unless `ring` is `"default"`. */
function spend(
  fixture: Fixture,
  sender: Sender,
  options: Readonly<{ ring?: Address | "default"; payer?: Address; asset?: Address }> = {},
): ConfidentialTransfer {
  const ring = options.ring === "default" ? undefined : (options.ring ?? fixture.ringProgramId);
  return new ConfidentialTransfer(
    sender.keypair.shieldedAddress(),
    [noteInput(sender.keypair, 10_000n, ring, options.asset)],
    options.payer ?? fixture.authority,
  );
}

/** The hidden owner's rail over `transfer`. */
function rail(
  input: Readonly<{
    fixture: Fixture;
    sender: Sender;
    transfer: ConfidentialTransfer;
    state?: AnonymousRingState;
    keys?: WalletKeys;
    signer?: AnonymousSpendSigner;
    withdrawal?: TransactWithdrawal;
  }>,
): AnonymousTransfer {
  const { fixture, sender } = input;
  const owner = CustomRingTransfer.new({
    ringProgramId: fixture.ringProgramId,
    keys: input.keys ?? walletKeys(sender.keypair),
    transfer: input.transfer,
    assets,
  });
  return (input.withdrawal === undefined ? owner : owner.withWithdrawalAccounts(input.withdrawal))
    .withAnonymousSigner(
      input.signer ?? signingKeySpendSigner(sender.signing),
      input.state ?? AnonymousRingState.create(fixture.ringProgramId, 0n),
    )
    .withTagRandom(firstFreeIndex);
}

/** The first free index of every draw, each test pins its tags on it. */
function firstFreeIndex(length: number): Uint8Array {
  return new Uint8Array(length);
}

function addressOf(
  fixture: Fixture,
  owner: ShieldedKeypair,
  pairing: Pairing = Pairing.any(),
): Promise<RingAddress> {
  return ringAddressOf({ keys: walletKeys(owner), ring: fixture.ringProgramId, index: 0, pairing });
}

function inboxOf(fixture: Fixture, to: RingAddress): Bytes32 {
  return inboxKey(ringIdField(fixture.ringProgramId), to.recipient.viewingPublicKey);
}

/** The anonymous audit request, its circuit the key the program verifies under. */
function anonymousAudit(fixture: Fixture) {
  const audit = fixture.ringRequests.find((request) => request.kind === "anonymousAudit");
  if (audit?.kind !== "anonymousAudit") throw new Error("no anonymous audit request");
  return { audit, circuit: ringCircuitType(ringProofCircuit(audit)) };
}

/** A sender whose earlier inbox payment to `to` landed at leaf 40 of `treeId`, pinned to seven of nine decoys. */
function pairedSender(
  fixture: Fixture,
  to: RingAddress,
  treeId: number,
): Readonly<{ state: AnonymousRingState; contact: SentFirstContact }> {
  const contact: SentFirstContact = {
    recipient: to.recipient.viewingPublicKey,
    treeId,
    leafIndex: 40n,
    utxoHash: small(0x90),
    slotSecret: small(0x91),
    blinding: small(0x92),
    epoch: EPOCH,
    index: tagIndex(0),
    asset: SOL_MINT,
    amount: 500n,
  };
  const decoys = Array.from({ length: 9 }, (_, leaf) => ({
    treeId,
    leafIndex: BigInt(leaf),
    hash: small(0xa0 + leaf),
  }));
  for (const decoy of decoys) fixture.placeLeaf(treeAddress(treeId), decoy.hash, decoy.leafIndex);
  fixture.placeLeaf(treeAddress(treeId), contact.utxoHash, contact.leafIndex);
  const state = AnonymousRingState.create(fixture.ringProgramId, 0n)
    .recordFirstContact(contact)
    .rememberDecoys(decoys)
    .pinAnchors();
  return { state, contact };
}

function noProofs(fixture: Fixture): void {
  expect(fixture.ringRequests).toHaveLength(0);
  expect(fixture.sppCalls).toHaveLength(0);
}

function photonAnswering(answer: () => Response): ZolanaIndexer {
  return new ZolanaIndexer(
    new ZolanaApi({ url: "https://indexer.example", fetch: async () => answer() }),
  );
}

describe("anonymous ring payment", () => {
  it("tags a payment from its address's inbox stream, the recipient opens it and the auditor every hash", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    expect(call.circuit.kind).toBe("ringAnonymous");
    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "anonymous"]);
    expect([data.fullOpenings, data.keyEscrow, data.anchor]).toEqual([false, false, undefined]);
    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inboxOf(fixture, to), EPOCH, tagIndex(0)));
    await checkAccounts(instruction, { fixture, data, prefix: [], payer: fixture.authority });
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    checkRingBlindings(call, data);
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-v2-4-2");
    expect([audit.inputCount, audit.inputs.length]).toEqual([1, 4]);
    expect(audit.outputs.map((slot) => [slot.stream.inbox, slot.stream.self])).toEqual([
      [false, true],
      [true, false],
    ]);
    const note = await openDelivered({
      fixture,
      keys: walletKeys(bob),
      recipient: { kind: "address", ring: fixture.ringProgramId, index: 0 },
      call,
      data,
      slotIndex: 1,
    });
    expect(note?.utxo.amount).toBe(400n);
    expect(note?.utxoHash).toEqual(payment.hash);
    expect(proven.epoch).toBe(EPOCH);
    expect(proven.firstContacts).toHaveLength(1);
    const contact = itemAt(proven.firstContacts, 0);
    expect(contact).toMatchObject({ index: 0, amount: 400n, utxoHash: payment.hash });
    expect(contact.recipient.equals(to.recipient.viewingPublicKey)).toBe(true);
  });

  it.each([
    ["the output tree", TREE_ID, 2],
    ["a tree outside the transfer", 5, 1],
  ] as const)(
    "pairs on a first contact in %s, its path fetched among seven decoys",
    async (_, treeId, anchorSlot) => {
      const fixture = await anonymousRing();
      const sender = anonymousSender();
      const bob = ShieldedKeypair.generate();
      const to = await addressOf(fixture, bob);
      const { state, contact } = pairedSender(fixture, to, treeId);
      const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client);
      const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

      const payment = data.outputs[1];
      if (payment?.kind !== "anonymous") throw new Error("no payment slot");
      expect(payment.tag).toEqual(pairTag(pairKey(contact.slotSecret), EPOCH, tagIndex(0)));
      expect(data.anchor).toEqual({ tree: anchorSlot, rootIndex: ANCHOR_ROOT_INDEX });
      const tree = treeAddress(treeId);
      const anchored = fixture.anchorTree(tree);
      expect(proven.anchor).toEqual({ tree, rootIndex: ANCHOR_ROOT_INDEX, root: anchored.root });
      await checkAccounts(instruction, {
        fixture,
        data,
        prefix: tree === TREE ? [] : [{ address: tree, role: AccountRole.READONLY }],
        payer: fixture.authority,
      });
      expect(fixture.merkleRequests).toHaveLength(1);
      const request = itemAt(fixture.merkleRequests, 0);
      expect(request.tree).toBe(tree);
      expect(request.leaves).toHaveLength(8);
      expect(request.leaves).toContainEqual(contact.utxoHash);
      checkAudit(fixture, data, {
        kind: "anonymousAudit",
        epoch: EPOCH,
        firstContactRoot: anchored.root,
      });
      checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
      const { audit } = anonymousAudit(fixture);
      expect(audit.anchor).toMatchObject({
        treeId: treeIdField(treeId),
        slotSecret: contact.slotSecret,
        pathIndex: 40n,
        path: anchored.path(40),
      });
      expect(audit.outputs[1]?.stream).toMatchObject({ pair: true, inbox: false, index: 0 });
      // A pair payment opens no new first contact.
      expect(proven.firstContacts).toEqual([]);
    },
  );

  it("refuses a first contact path its tree's root history does not hold before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    fixture.accounts.set(treeAddress(5), anchorTreeAccount(small(0x72)));
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(
      ringError("RING_ANCHOR_INVALID", { reason: "root", rootIndex: ANCHOR_ROOT_INDEX }),
    );
    noProofs(fixture);
  });

  it("refuses a fault on any pinned proof as it refuses one on the anchor, before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state, contact } = pairedSender(fixture, to, 5);
    const leaves = state.pairAnchor(contact.recipient, EPOCH)?.leaves ?? [];
    const served = fixture.client.getMerkleProofs;
    type Proofs = Awaited<ReturnType<typeof served>>["proofs"];
    const on = (proof: Proofs[number], leaf: Bytes32) =>
      Buffer.from(proof.leaf).equals(Buffer.from(leaf));
    const faults: readonly ((proofs: Proofs, leaf: Bytes32) => Proofs)[] = [
      (proofs, leaf) => proofs.filter((proof) => !on(proof, leaf)),
      (proofs, leaf) =>
        proofs.map((proof) =>
          on(proof, leaf)
            ? { ...proof, path: proof.path.map((node, at) => (at === 3 ? small(0x7f) : node)) }
            : proof,
        ),
      (proofs, leaf) =>
        proofs.map((proof) => {
          if (!on(proof, leaf)) return proof;
          const path = proof.path.map((node, at) => {
            if (at !== 3) return node;
            const flipped = new Uint8Array(node) as Bytes32;
            flipped[31] = (flipped[31] ?? 0) ^ 1;
            return flipped;
          });
          const root = path.reduce(
            ({ node, position }, sibling) => ({
              node: (position & 1n) === 0n ? poseidon([node, sibling]) : poseidon([sibling, node]),
              position: position >> 1n,
            }),
            { node: proof.leaf as Uint8Array, position: proof.leafIndex },
          ).node as Bytes32;
          return { ...proof, path, root };
        }),
      (proofs, leaf) =>
        proofs.map((proof) =>
          on(proof, leaf) ? { ...proof, rootIndex: proof.rootIndex ^ 1 } : proof,
        ),
      (proofs, leaf) =>
        proofs.map((proof) =>
          on(proof, leaf) ? { ...proof, leafIndex: proof.leafIndex ^ 1n } : proof,
        ),
    ];
    expect(leaves).toHaveLength(ANCHOR_DECOYS + 1);
    for (const leaf of leaves)
      for (const fault of faults) {
        fixture.client.getMerkleProofs = async (tree, requested) => {
          const response = await served(tree, requested);
          return { ...response, proofs: fault(response.proofs, leaf) };
        };
        await expect(
          rail({ fixture, sender, transfer: spend(fixture, sender), state })
            .withPayment({ to, asset: SOL_MINT, amount: 400n })
            .prove(fixture.client),
        ).rejects.toThrow(
          ringError("RING_ANCHOR_INVALID", {
            reason: "leaves",
            tree: treeAddress(5),
            recipient: hex(to.recipient.viewingPublicKey.toBytes()),
          }),
        );
      }
    noProofs(fixture);
  });

  it("refuses a first contact on a paused tree before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    const paused = anchorTreeAccount(fixture.anchorTree(treeAddress(5)).root);
    paused.data[1] = TREE_STATE_PAUSED;
    fixture.accounts.set(treeAddress(5), paused);
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_ANCHOR_INVALID", { reason: "paused", tree: treeAddress(5) }));
    noProofs(fixture);
  });

  it("names the pinned leaves on every anchor read of a contact while the pool grows", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state, contact } = pairedSender(fixture, to, TREE_ID);
    const later = Array.from({ length: 32 }, (_, leaf) => ({
      treeId: TREE_ID,
      leafIndex: BigInt(100 + leaf),
      hash: small(0x40 + leaf),
    }));
    for (const leaf of later) fixture.placeLeaf(TREE, leaf.hash, leaf.leafIndex);
    const prove = (paying: AnonymousRingState) =>
      rail({ fixture, sender, transfer: spend(fixture, sender), state: paying })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client);
    await prove(state);
    await prove(state.rememberDecoys(later));

    expect(fixture.merkleRequests).toHaveLength(2);
    expect(itemAt(fixture.merkleRequests, 1).leaves).toEqual(
      itemAt(fixture.merkleRequests, 0).leaves,
    );
    expect(itemAt(fixture.merkleRequests, 0).leaves).toEqual(
      state.pairAnchor(contact.recipient, EPOCH)?.leaves,
    );
  });

  it("reads no first contact path before the transfer is approved", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, TREE_ID);
    const declined = new Error("declined");
    await expect(
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .proveApproved(fixture.client, {
          transaction: {},
          approve: () => Promise.reject(declined),
        }),
    ).rejects.toBe(declined);
    expect(fixture.merkleRequests).toEqual([]);
    noProofs(fixture);
  });

  it("names the first contact to retire when the indexer refuses its pinned leaves, a retryable failure passes", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    const prove = () =>
      rail({ fixture, sender, transfer: spend(fixture, sender), state })
        .withPayment({ to, asset: SOL_MINT, amount: 400n })
        .prove(fixture.client);
    const failing = (retryable: boolean) => async () => {
      throw new ClientError("CLIENT_INDEXER", {
        details: { method: "getMerkleProofs", retryable },
      });
    };
    fixture.client.getMerkleProofs = failing(false);
    await expect(prove()).rejects.toThrow(
      expect.objectContaining({
        code: "RING_ANCHOR_INVALID",
        causeCode: "CLIENT_INDEXER",
        details: {
          reason: "leaves",
          tree: treeAddress(5),
          recipient: hex(to.recipient.viewingPublicKey.toBytes()),
        },
      }),
    );
    fixture.client.getMerkleProofs = failing(true);
    await expect(prove()).rejects.toThrow(
      expect.objectContaining({
        code: "CLIENT_INDEXER",
        details: expect.objectContaining({ retryable: true }),
      }),
    );
    noProofs(fixture);
  });

  it("retires the first contact when an indexer past the staging slot withholds a leaf, answers malformed or refuses", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    const context = { blockTime: 0, slot: 1 };
    for (const [answer, causeCode] of [
      [{ result: { context, proofs: [] } }, undefined],
      [{ result: { context, proofs: [{ leaf: 7 }] } }, "CLIENT_INVALID_RPC_RESPONSE"],
      [{ error: { code: -32600, message: "Record Not Found" } }, "CLIENT_INDEXER"],
    ] as const) {
      const indexer = photonAnswering(() =>
        Response.json({ jsonrpc: "2.0", id: "test-account", ...answer }),
      );
      fixture.client.getMerkleProofs = (tree, leaves) => indexer.getMerkleProofs(tree, leaves);
      await expect(
        rail({ fixture, sender, transfer: spend(fixture, sender), state })
          .withPayment({ to, asset: SOL_MINT, amount: 400n })
          .prove(fixture.client),
      ).rejects.toThrow(
        expect.objectContaining({
          code: "RING_ANCHOR_INVALID",
          causeCode,
          details: {
            reason: "leaves",
            tree: treeAddress(5),
            recipient: hex(to.recipient.viewingPublicKey.toBytes()),
          },
        }),
      );
    }
    noProofs(fixture);
  });

  it("keeps the first contact through a transport failure of the read", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    for (const answer of [
      () => new Response(null, { status: 408 }),
      () => new Response(null, { status: 425 }),
    ]) {
      const indexer = photonAnswering(answer);
      fixture.client.getMerkleProofs = (tree, leaves) => indexer.getMerkleProofs(tree, leaves);
      await expect(
        rail({ fixture, sender, transfer: spend(fixture, sender), state })
          .withPayment({ to, asset: SOL_MINT, amount: 400n })
          .prove(fixture.client),
      ).rejects.toThrow(
        expect.objectContaining({
          code: "CLIENT_INDEXER",
          details: expect.objectContaining({ retryable: true }),
        }),
      );
    }
    noProofs(fixture);
  });

  it("keeps the first contact while the indexer lags the staging slot", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const { state } = pairedSender(fixture, to, 5);
    let reads = 0;
    fixture.client.getMerkleProofs = async () => {
      reads += 1;
      return { context: { slot: 0n, blockTime: 0n }, proofs: [] };
    };
    vi.useFakeTimers();
    try {
      const outcome = expect(
        rail({ fixture, sender, transfer: spend(fixture, sender), state })
          .withPayment({ to, asset: SOL_MINT, amount: 400n })
          .prove(fixture.client),
      ).rejects.toThrow(
        expect.objectContaining({
          code: "CLIENT_INDEXER_NOT_CAUGHT_UP",
          details: {
            target: "1",
            latest: "0",
            attempts: DEFAULT_INDEXER_POLL_CONFIG.numRetries + 1,
          },
        }),
      );
      let settled = false;
      const settle = (): void => {
        settled = true;
      };
      void outcome.then(settle, settle);
      while (!settled) await vi.advanceTimersByTimeAsync(1_000);
      await outcome;
    } finally {
      vi.useRealTimers();
    }
    expect(reads).toBe(DEFAULT_INDEXER_POLL_CONFIG.numRetries + 1);
    noProofs(fixture);
  });

  it("takes the inbox stream when the address's rows refuse the first contact", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob, Pairing.of([{ mint: SOL_MINT, minAmount: 1_000n }]));
    const { state } = pairedSender(fixture, to, TREE_ID);
    const inbox = inboxOf(fixture, to);
    fixture.publishTags([inboxTag(inbox, EPOCH, tagIndex(0))]);
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), state })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data } = await expanded(fixture, proven, "anonymous");

    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inbox, EPOCH, tagIndex(0)));
    expect(data.anchor).toBeUndefined();
    expect(fixture.merkleRequests).toEqual([]);
    expect(proven.firstContacts.map((contact) => contact.index)).toEqual([0]);
  });

  it("pays an address whose every inbox index outsiders already used in the epoch", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const inbox = inboxOf(fixture, to);
    fixture.publishTags(
      Array.from({ length: J_INBOX }, (_, index) => inboxTag(inbox, EPOCH, tagIndex(index))),
    );
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data } = await expanded(fixture, proven, "anonymous");

    const payment = data.outputs[1];
    if (payment?.kind !== "anonymous") throw new Error("no payment slot");
    expect(payment.tag).toEqual(inboxTag(inbox, EPOCH, tagIndex(0)));
  });

  it("keeps a payment on its own slot when a later send on the shared transfer follows it", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const outside = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const transfer = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer }).withPayment({
      to,
      asset: SOL_MINT,
      amount: 400n,
    });
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await paying.prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual([
      "anonymous",
      "anonymous",
      "exit",
      "anonymous",
    ]);
    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    const note = await openDelivered({
      fixture,
      keys: walletKeys(bob),
      recipient: { kind: "address", ring: fixture.ringProgramId, index: 0 },
      call,
      data,
      slotIndex: 1,
    });
    expect(note?.utxo.amount).toBe(400n);
  });

  it("completes through a remote holder that forwards only port methods", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const bob = ShieldedKeypair.generate();
    const to = await addressOf(fixture, bob);
    const local = walletKeys(sender.keypair);
    const called = new Set<string>();
    const track = <T>(name: string, value: T): T => {
      called.add(name);
      return value;
    };
    const remote: WalletKeys & RingKeys = {
      address: () => track("address", local.address()),
      viewingPublicKeys: () => track("viewingPublicKeys", local.viewingPublicKeys()),
      decrypt: (requests) => track("decrypt", local.decrypt(requests)),
      derive: (requests) => track("derive", local.derive(requests)),
      transactionKeys: (requests) => track("transactionKeys", local.transactionKeys(requests)),
      ringAddressKeys: (ring, indexes) =>
        track("ringAddressKeys", local.ringAddressKeys(ring, indexes)),
      ringDeliverySecrets: (requests) =>
        track("ringDeliverySecrets", local.ringDeliverySecrets(requests)),
      ringChangeKey: (ring) => track("ringChangeKey", local.ringChangeKey(ring)),
      senderViewTags: (counters) => track("senderViewTags", local.senderViewTags(counters)),
      prove: (inputs, context) => track("prove", local.prove(inputs, context)),
      proveMerge: (inputs, context) => track("proveMerge", local.proveMerge(inputs, context)),
    };
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender), keys: remote })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(call.authority).toBe(remote);
    expect([...called].sort()).toEqual([
      "address",
      "ringAddressKeys",
      "ringChangeKey",
      "transactionKeys",
    ]);
  });
});

describe("anonymous ring exits and entries", () => {
  it("exits a note to the default ring under scheme 3 with SeedOut in the disclosure", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const outside = ShieldedKeypair.generate();
    const transfer = spend(fixture, sender);
    transfer.sendDefaultRing(outside.shieldedAddress(), SOL_MINT, 300n);
    const proven = await rail({ fixture, sender, transfer }).prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.outputs.map((output) => output.kind)).toEqual(["anonymous", "exit"]);
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.seedOut).toEqual(call.proofInputs.outputBlindingSeed());
    const exit = data.outputs[1];
    if (exit?.kind !== "exit") throw new Error("no exit slot");
    const viewing = outside.viewingKey();
    const opened = decodeConfidential(
      viewing.decryptUtxo(
        exit.payload.subarray(33),
        X25519PublicKey.fromBytes(call.data.txViewingPk),
        data.salt,
        1,
      ),
    );
    viewing.destroy();
    expect(opened.amount).toBe(300n);
    expect(proven.firstContacts).toEqual([]);
  });

  it("spends a default-ring note under the entry key, every input opened in full", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const proven = await rail({
      fixture,
      sender,
      transfer: spend(fixture, sender, { ring: "default" }),
    })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
    const { data, call } = await expanded(fixture, proven, "anonymous");

    expect(data.fullOpenings).toBe(true);
    // Input byte bit 7 names the entry key.
    expect((RingTransactData.encode(data)[2] ?? 0) & 0x80).toBe(0x80);
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    const disclosure = checkDisclosure(fixture, call, data, sender.keypair.shieldedAddress());
    expect(disclosure.kind === "anonymous" && disclosure.inputs.kind).toBe("openings");
    const { audit, circuit } = anonymousAudit(fixture);
    expect(circuit).toBe("custom-ring-audit-anonymous-entry-v2-8-2");
    expect([audit.layout.fullOpenings, audit.inputs.length]).toEqual([true, 8]);
  });

  it("counts an entry's default owner tag, its setup instructions and fee before approval and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await checkFrameCounted(fixture, {
      payer: fixture.authority,
      prove: (approval) =>
        rail({ fixture, sender, transfer: spend(fixture, sender, { ring: "default" }) })
          .withPayment({ to, asset: SOL_MINT, amount: 400n })
          .proveApproved(fixture.client, approval),
    });
  });

  it("refuses an entry input that carries data before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const input = ProofInputUtxo.fromKeypair(
      new Utxo({
        owner: sender.keypair.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10_000n,
        blinding: randomBlinding(),
      }),
      sender.keypair,
      { dataHash: small(0x55) },
      TREE_ID,
    );
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      [input],
      fixture.authority,
    );
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ENTRY_INPUT_DATA", { index: 0 }),
    );
    noProofs(fixture);
  });

  it("refuses ring notes beside a default-ring note before the entry width and any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      [
        noteInput(sender.keypair, 10_000n),
        ...Array.from({ length: 8 }, () =>
          noteInput(sender.keypair, 1_000n, fixture.ringProgramId),
        ),
      ],
      fixture.authority,
    );
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_ENTRY_RING_INPUT", { index: 1 }),
    );
    noProofs(fixture);
  });

  it("refuses a note of another owner than the sender before any proof", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const other = ShieldedKeypair.generate();
    const transfer = new ConfidentialTransfer(
      other.shieldedAddress(),
      [noteInput(other, 10_000n, fixture.ringProgramId)],
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    await expect(
      rail({ fixture, sender, transfer })
        .withPayment({ to, asset: SOL_MINT, amount: 10_000n })
        .prove(fixture.client),
    ).rejects.toThrow(ringError("RING_MIXED_OWNERS", { index: 0 }));
    noProofs(fixture);
  });

  it("refuses an address slot among anonymous inputs like Rust `check_anonymous_slots`", () => {
    const owner = ShieldedKeypair.generate();
    const reserved = ProofInputUtxo.address(owner.signingPublicKey(), small(7));
    const proofInputs = { inputUtxos: [reserved], outputs: [] } as unknown as SppProofInputs;
    expect(() => checkAnonymousSlots(proofInputs)).toThrow(
      ringError("RING_ANONYMOUS_SLOT_INVALID"),
    );
  });

  it("refuses an exit to the sender's own ring address key and to a payee's", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const own = await addressOf(fixture, sender.keypair);
    const issued = AnonymousRingState.create(fixture.ringProgramId, 0n).issue(0, Pairing.any());
    const toOwn = spend(fixture, sender);
    toOwn.sendDefaultRing(own.recipient, SOL_MINT, 100n);
    await expect(
      rail({ fixture, sender, transfer: toOwn, state: issued }).prove(fixture.client),
    ).rejects.toThrow(ringError("RING_ADDRESS_EXIT"));
    const bob = await addressOf(fixture, ShieldedKeypair.generate());
    const toPayee = spend(fixture, sender);
    const paying = rail({ fixture, sender, transfer: toPayee }).withPayment({
      to: bob,
      asset: SOL_MINT,
      amount: 100n,
    });
    toPayee.sendDefaultRing(bob.recipient, SOL_MINT, 100n);
    await expect(paying.prove(fixture.client)).rejects.toThrow(ringError("RING_ADDRESS_EXIT"));
    noProofs(fixture);
  });

  it("refuses a ring output no payment planned", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const transfer = spend(fixture, sender);
    transfer.send(ShieldedKeypair.generate().shieldedAddress(), SOL_MINT, 100n);
    await expect(rail({ fixture, sender, transfer }).prove(fixture.client)).rejects.toThrow(
      ringError("RING_UNPLANNED_OUTPUT", { slotIndex: 1 }),
    );
    noProofs(fixture);
  });
});

describe("anonymous ring signer and epoch", () => {
  it("refuses another signer, a hidden owner that signs in public, a partial key holder and another ring", async () => {
    const sender = anonymousSender();
    const hidden = sender.keypair.shieldedAddress().solanaAddress();
    const refused = async (
      fixture: Fixture,
      transfer: Promise<ProvenRingTransfer>,
      code: string,
    ): Promise<void> => {
      await expect(transfer).rejects.toThrow(ringError(code));
      noProofs(fixture);
    };
    const ring = await anonymousRing();
    await refused(
      ring,
      rail({
        fixture: ring,
        sender,
        transfer: spend(ring, sender),
        signer: signingKeySpendSigner(SigningKey.generate()),
      }).prove(ring.client),
      "RING_ANONYMOUS_SIGNER_MISMATCH",
    );
    await refused(
      ring,
      rail({ fixture: ring, sender, transfer: spend(ring, sender, { payer: hidden }) }).prove(
        ring.client,
      ),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const coSigned = await anonymousRing({
      coSigner: { signer: hidden, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
    });
    await refused(
      coSigned,
      rail({ fixture: coSigned, sender, transfer: spend(coSigned, sender) }).prove(coSigned.client),
      "RING_ANONYMOUS_SIGNER_LINKS_OWNER",
    );
    const local = walletKeys(sender.keypair);
    const partial: WalletKeys = {
      address: () => local.address(),
      viewingPublicKeys: () => local.viewingPublicKeys(),
      decrypt: (requests) => local.decrypt(requests),
      derive: (requests) => local.derive(requests),
      transactionKeys: (requests) => local.transactionKeys(requests),
      prove: (inputs, context) => local.prove(inputs, context),
      proveMerge: (inputs, context) => local.proveMerge(inputs, context),
    };
    await refused(
      ring,
      rail({ fixture: ring, sender, transfer: spend(ring, sender), keys: partial }).prove(
        ring.client,
      ),
      "RING_KEYS_REQUIRED",
    );
    const confidential = await ringFixture();
    await refused(
      confidential,
      rail({ fixture: confidential, sender, transfer: spend(confidential, sender) }).prove(
        confidential.client,
      ),
      "RING_NOT_ANONYMOUS",
    );
    const other = await anonymousRing();
    const foreign = await addressOf(other, ShieldedKeypair.generate());
    expect(() =>
      rail({ fixture: ring, sender, transfer: spend(ring, sender) }).withPayment({
        to: foreign,
        asset: SOL_MINT,
        amount: 1n,
      }),
    ).toThrow(ringError("RING_FOREIGN_RING", { address: other.ringProgramId }));
  });

  it("names the epoch before the landing slot's one epoch late and refuses a later slot", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const proven = await rail({ fixture, sender, transfer: spend(fixture, sender) }).prove(
      fixture.client,
    );
    const previousEpoch = async (slot: bigint): Promise<boolean> => {
      const data = (await proven.instructionAt(slot)).data;
      if (data === undefined) throw new Error("no instruction data");
      return RingTransactData.parse(data.subarray(1), "anonymous").previousEpoch;
    };
    expect(await previousEpoch(1n)).toBe(false);
    expect(await previousEpoch(EPOCH_SLOTS)).toBe(true);
    await expect(
      Promise.resolve().then(() => proven.instructionAt(2n * EPOCH_SLOTS)),
    ).rejects.toThrow(ringError("RING_EPOCH_PASSED", { proofEpoch: "0", currentEpoch: "2" }));
  });
});

describe("anonymous ring transfer builder", () => {
  /** A spend of `notes` notes of 10, of the ring or the default ring, on a ring a co-signer guards when `policy`. */
  async function anonymousSpend(
    input: Readonly<{
      notes: number;
      amount: bigint;
      ring?: "default";
      /** Default-ring notes beside the ring notes, a transfer may spend them. */
      defaultNotes?: readonly bigint[];
      /** Default-ring notes carrying a data hash. */
      dataNotes?: readonly Readonly<{ amount: bigint; dataHash: Bytes32 }>[];
      policy?: boolean;
      withdraw?: boolean;
    }>,
  ) {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await anonymousRing(
      input.policy === true
        ? {
            table: buildRuleTable({
              rules: [
                {
                  subject: "sender",
                  source: { kind: "lists", present: [ListId.allow], absent: [] },
                  guard: { kind: "always" },
                },
              ],
              limits: [{ asset: memberOfAsset(SOL_MINT), cap: 0n, cosignAbove: 1n }],
            }),
            records: [
              {
                member: memberOfIdentity(
                  sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
                ),
                lists: 1n,
              },
            ],
            coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] },
          }
        : {},
    );
    const notes: readonly Readonly<{ amount: bigint; ring?: Address; dataHash?: Bytes32 }>[] = [
      ...Array.from({ length: input.notes }, () =>
        input.ring === "default" ? { amount: 10n } : { amount: 10n, ring: fixture.ringProgramId },
      ),
      ...(input.defaultNotes ?? []).map((amount) => ({ amount })),
      ...(input.dataNotes ?? []),
    ];
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    wallet._replace({
      utxos: notes.map((note, index) => ({
        utxo: new Utxo({
          owner: sender.keypair.signingPublicKey(),
          asset: SOL_MINT,
          amount: note.amount,
          blinding: randomBlinding(),
          ...(note.ring === undefined ? {} : { ringProgramId: note.ring }),
        }),
        outputContext: { hash: small(index + 1), tree: TREE, leafIndex: BigInt(index) },
        nullifier: small(index + 100),
        ...(note.dataHash === undefined ? {} : { dataHash: note.dataHash }),
        spent: false,
      })),
      transactions: [],
      nullifiers: new Set(),
    });
    const requests: RingApprovalRequest[] = [];
    const params = {
      client: { ...fixture.client, getLatestBlockhash: async () => BLOCKHASH },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      feePayer: fixture.authority,
      amount: input.amount,
      priorityFeeLamports: 5_000n,
      ...(input.policy === true ? { cosigner: coSigner } : {}),
      approve: async (request: RingApprovalRequest) => {
        requests.push(request);
        return approveRingUnattended(request);
      },
      anonymous: {
        signer: signingKeySpendSigner(sender.signing),
        state: AnonymousRingState.create(fixture.ringProgramId, 0n),
      },
    };
    const build =
      input.withdraw === true
        ? buildRingWithdrawalTransaction({ ...params, recipient: randomAddress() })
        : buildRingTransferTransaction({
            ...params,
            recipient: await addressOf(fixture, ShieldedKeypair.generate()),
            ...(input.ring === "default"
              ? { inputs: "default" as const }
              : input.defaultNotes === undefined
                ? {}
                : { inputs: "ring-or-default" as const }),
          });
    return { fixture, requests, build };
  }

  it("spends the widest commitment class and refuses a payment past it before approval", async () => {
    const widest = await anonymousSpend({ notes: 32, amount: 315n });
    expect(transactionSize(await widest.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(widest.requests).toHaveLength(1);
    expect(widest.fixture.sppCalls.at(-1)?.proofInputs.checkShape()).toEqual({
      inputs: 32,
      outputs: 2,
    });
    const wider = await anonymousSpend({ notes: 33, amount: 325n });
    await expect(wider.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 32 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("refuses a withdrawal of the widest class past one transaction before approval as too many notes", async () => {
    const wide = await anonymousSpend({ notes: 32, amount: 315n, policy: true, withdraw: true });
    await expect(wide.build).rejects.toMatchObject({
      code: "RING_BUILD_WITHDRAWAL",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { selected: 32, limit: TRANSACTION_SIZE_LIMIT } },
    });
    expect(wide.requests).toEqual([]);
    noProofs(wide.fixture);
  });

  it("spends the entry key's input class of default-ring notes and refuses one more", async () => {
    const entry = await anonymousSpend({ notes: 8, amount: 75n, ring: "default", policy: true });
    expect(transactionSize(await entry.build)).toBeLessThanOrEqual(TRANSACTION_SIZE_LIMIT);
    expect(entry.requests).toHaveLength(1);
    const wider = await anonymousSpend({ notes: 9, amount: 85n, ring: "default" });
    await expect(wider.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_TOO_MANY_INPUTS",
      cause: { details: { maximum: 8 } },
    });
    expect(wider.requests).toEqual([]);
    noProofs(wider.fixture);
  });

  it("funds an entry from default-ring notes without data", async () => {
    const entry = await anonymousSpend({
      notes: 2,
      amount: 15n,
      ring: "default",
      dataNotes: [{ amount: 100n, dataHash: small(0x55) }],
    });
    await entry.build;
    expect(entry.requests[0]?.intent).toMatchObject({ defaultFunding: 20n });
  });

  it("funds an entry from a default-ring note whose data hash is zero, like Rust `carries_no_data`", async () => {
    const entry = await anonymousSpend({
      notes: 0,
      amount: 15n,
      ring: "default",
      dataNotes: [{ amount: 20n, dataHash: small(0) }],
    });
    await entry.build;
    expect(entry.requests[0]?.intent).toMatchObject({ defaultFunding: 20n });
  });

  it("funds a ring-or-default payment from ring notes alone, else default-ring notes alone, never both", async () => {
    const ringAlone = await anonymousSpend({ notes: 3, amount: 25n, defaultNotes: [100n] });
    await ringAlone.build;
    expect(ringAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 0n });
    const defaultAlone = await anonymousSpend({ notes: 3, amount: 40n, defaultNotes: [100n] });
    await defaultAlone.build;
    expect(defaultAlone.requests[0]?.intent).toMatchObject({ defaultFunding: 100n });
    const both = await anonymousSpend({ notes: 3, amount: 50n, defaultNotes: [25n] });
    await expect(both.build).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_INSUFFICIENT_BALANCE",
    });
    expect(both.requests).toEqual([]);
    noProofs(both.fixture);
  });

  it("compiles a payment proven in the epoch before the slot it compiles at under the previous epoch", async () => {
    const fixture = await anonymousRing();
    const sender = anonymousSender();
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    const wallet = new Wallet({ identity: sender.keypair.shieldedAddress() });
    wallet._replace({
      utxos: [
        {
          utxo: new Utxo({
            owner: sender.keypair.signingPublicKey(),
            asset: SOL_MINT,
            amount: 10_000n,
            blinding: randomBlinding(),
            ringProgramId: fixture.ringProgramId,
          }),
          outputContext: { hash: small(1), tree: TREE, leafIndex: 0n },
          nullifier: small(100),
          spent: false,
        },
      ],
      transactions: [],
      nullifiers: new Set(),
    });
    let proved = false;
    const transaction = await buildRingTransferTransaction({
      client: {
        ...fixture.client,
        getSlot: async () => (proved ? EPOCH_SLOTS : 1n),
        proveAnonymousRingTransact: async (input) => {
          proved = true;
          return fixture.client.proveAnonymousRingTransact(input);
        },
        getLatestBlockhash: async () => BLOCKHASH,
      },
      ringProgramId: fixture.ringProgramId,
      wallet,
      keys: walletKeys(sender.keypair),
      feePayer: fixture.authority,
      recipient: to,
      amount: 400n,
      anonymous: {
        signer: signingKeySpendSigner(sender.signing),
        state: AnonymousRingState.create(fixture.ringProgramId, 0n),
      },
    });
    const data = decompileTransactionMessage(
      getCompiledTransactionMessageDecoder().decode(transaction.messageBytes),
    ).instructions.find(
      (instruction) => instruction.programAddress === fixture.ringProgramId,
    )?.data;
    if (data === undefined) throw new Error("no ring instruction");
    expect(RingTransactData.parse(data.subarray(1), "anonymous").previousEpoch).toBe(true);
  });
});

const MINT = address("So11111111111111111111111111111111111111112");
const STRANGER = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
/** A keypair address, on the ed25519 curve. */
const DESTINATION = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
const TOKEN_ACCOUNT = await associatedTokenAddress(STRANGER, MINT, SPL_TOKEN_PROGRAM_ID);

function tokenAccount(
  owner: Address,
  others: Readonly<{ mint?: Address; delegate?: Address; closeAuthority?: Address }> = {},
): RpcAccount {
  const key = (value: Address | undefined) => (value === undefined ? none<Address>() : some(value));
  return {
    owner: SPL_TOKEN_PROGRAM_ID,
    lamports: 1n,
    data: new Uint8Array(
      getTokenEncoder().encode({
        mint: others.mint ?? MINT,
        owner,
        amount: 0n,
        delegate: key(others.delegate),
        state: AccountState.Initialized,
        isNative: none(),
        delegatedAmount: 0n,
        closeAuthority: key(others.closeAuthority),
      }),
    ),
  };
}

/** An SPL or SOL withdrawal of 4 out of a ring note, the destination's account as the chain holds it. */
async function anonymousWithdrawal(
  input: Readonly<{
    sender: Sender;
    destination: Address;
    spl: boolean;
    accounts?: ReadonlyMap<Address, RpcAccount>;
    exitTokenOwner?: Address;
  }>,
): Promise<Readonly<{ fixture: Fixture; proven: Promise<ProvenRingTransfer> }>> {
  const fixture = await anonymousRing();
  for (const [key, account] of input.accounts ?? []) fixture.accounts.set(key, account);
  const { sender, destination } = input;
  const transfer = spend(fixture, sender, input.spl ? { asset: MINT } : {});
  let withdrawal: TransactWithdrawal;
  if (input.spl) {
    const [splTokenInterface, splInterfaceBump] = await splInterfaceWithBump(MINT);
    transfer.withdraw(
      MINT,
      4n,
      WithdrawalTarget.spl({
        recipientTokenAccount: destination,
        splTokenInterface,
        splInterfaceBump,
      }),
    );
    withdrawal = TransactWithdrawal.spl({
      mint: MINT,
      splTokenInterface,
      recipientTokenAccount: destination,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    });
  } else {
    transfer.withdraw(SOL_MINT, 4n, WithdrawalTarget.sol({ recipient: destination }));
    withdrawal = TransactWithdrawal.sol({ recipient: destination });
  }
  const anonymous = rail({ fixture, sender, transfer, withdrawal });
  return {
    fixture,
    proven: (input.exitTokenOwner === undefined
      ? anonymous
      : anonymous.withExitTokenOwner(input.exitTokenOwner)
    ).prove(fixture.client),
  };
}

function exitTokenOwnerOf(fixture: Fixture): Address | undefined {
  const call = itemAt(fixture.sppCalls, 0);
  return call.exitTokenOwner;
}

describe("anonymous ring withdrawal destination", () => {
  const sender = anonymousSender();
  const hidden = sender.keypair.shieldedAddress().solanaAddress();

  it("refuses an SPL destination naming the hidden owner or a second key before proving", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Address, RpcAccount | undefined, string])[] = [
      [TOKEN_ACCOUNT, tokenAccount(hidden), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [hidden, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [associated, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { delegate: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { closeAuthority: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
      ],
      [TOKEN_ACCOUNT, undefined, "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID"],
      [
        TOKEN_ACCOUNT,
        tokenAccount(STRANGER, { mint: STRANGER }),
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
    ];
    for (const [destination, account, code] of refusals) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination,
        spl: true,
        accounts: new Map(account === undefined ? [] : [[destination, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination }));
      noProofs(fixture);
    }
  });

  it("refuses a SOL recipient that is the hidden owner or holds data before proving", async () => {
    for (const [recipient, account, code] of [
      [hidden, undefined, "RING_ANONYMOUS_EXIT_LINKS_OWNER"],
      [DESTINATION, tokenAccount(STRANGER), "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA"],
      [
        DESTINATION,
        { owner: SYSTEM_PROGRAM, lamports: 1n, data: new Uint8Array(80) },
        "RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA",
      ],
    ] as const) {
      const { fixture, proven } = await anonymousWithdrawal({
        sender,
        destination: recipient,
        spl: false,
        accounts: new Map(account === undefined ? [] : [[recipient, account] as const]),
      });
      await expect(proven).rejects.toThrow(ringError(code, { destination: recipient }));
      noProofs(fixture);
    }
  });

  it("binds the SPL token account owner or no owner for a SOL recipient", async () => {
    const spl = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
    });
    await expanded(spl.fixture, await spl.proven, "anonymous");
    expect(exitTokenOwnerOf(spl.fixture)).toBe(STRANGER);
    const sol = await anonymousWithdrawal({ sender, destination: DESTINATION, spl: false });
    const { instruction, data } = await expanded(sol.fixture, await sol.proven, "anonymous");
    expect(exitTokenOwnerOf(sol.fixture)).toBeUndefined();
    await checkAccounts(instruction, {
      fixture: sol.fixture,
      data,
      prefix: [],
      payer: sol.fixture.authority,
      settlement: [
        { address: SOL_INTERFACE, role: AccountRole.WRITABLE },
        { address: DESTINATION, role: AccountRole.WRITABLE },
      ],
    });
  });

  const minted = new Map([
    [MINT, { owner: SPL_TOKEN_PROGRAM_ID, lamports: 1n, data: new Uint8Array(82) }],
  ]);

  it("takes a destination the transaction creates as the named owner's associated token account", async () => {
    const { fixture, proven } = await anonymousWithdrawal({
      sender,
      destination: TOKEN_ACCOUNT,
      spl: true,
      accounts: minted,
      exitTokenOwner: STRANGER,
    });
    await expanded(fixture, await proven, "anonymous");
    expect(exitTokenOwnerOf(fixture)).toBe(STRANGER);
  });

  const splLeg = (destination: Address): SettlementTransfer => ({
    kind: "spl",
    mint: MINT,
    isDeposit: false,
    amount: 4n,
    tokenAccount: destination,
    splInterfaceBump: 255,
  });

  const exitOwner = (
    input: Readonly<{
      transfers: readonly SettlementTransfer[];
      accounts: ReadonlyMap<Address, RpcAccount>;
      tokenOwner?: Address;
    }>,
  ) =>
    anonymousExitTokenOwner({
      client: { getAccount: async (key) => input.accounts.get(key) },
      transfers: input.transfers,
      hiddenOwner: addressBytes(hidden) as Bytes32,
      ...(input.tokenOwner === undefined ? {} : { tokenOwner: input.tokenOwner }),
    });

  const tokenOwnerOf = (account: RpcAccount) =>
    exitOwner({
      transfers: [splLeg(TOKEN_ACCOUNT)],
      accounts: new Map([[TOKEN_ACCOUNT, account]]),
    });

  it("refuses a named owner the destination or the withdrawals contradict", async () => {
    const associated = await associatedTokenAddress(hidden, MINT, SPL_TOKEN_PROGRAM_ID);
    const refusals: readonly (readonly [Parameters<typeof exitOwner>[0], string])[] = [
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: minted, tokenOwner: DESTINATION },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(TOKEN_ACCOUNT)], accounts: new Map(), tokenOwner: STRANGER },
        "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
      ],
      [
        { transfers: [splLeg(associated)], accounts: minted, tokenOwner: hidden },
        "RING_ANONYMOUS_EXIT_LINKS_OWNER",
      ],
      [
        {
          transfers: [splLeg(TOKEN_ACCOUNT)],
          accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
          tokenOwner: DESTINATION,
        },
        "RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH",
      ],
      [
        {
          transfers: [{ kind: "sol", isDeposit: false, amount: 4n, userSolAccount: DESTINATION }],
          accounts: new Map(),
          tokenOwner: STRANGER,
        },
        "RING_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH",
      ],
    ];
    for (const [input, code] of refusals)
      await expect(exitOwner(input)).rejects.toMatchObject({ code });
  });

  it("names the destination, the named owner and the token owner of a mismatch", async () => {
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT)],
        accounts: new Map([[TOKEN_ACCOUNT, tokenAccount(STRANGER)]]),
        tokenOwner: DESTINATION,
      }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_NAMED_OWNER_MISMATCH", {
        destination: TOKEN_ACCOUNT,
        named: DESTINATION,
        owner: STRANGER,
      }),
    );
  });

  it("refuses two SPL exits to different owners", async () => {
    const other = ShieldedKeypair.generate().shieldedAddress().solanaAddress();
    const second = await associatedTokenAddress(other, MINT, SPL_TOKEN_PROGRAM_ID);
    await expect(
      exitOwner({
        transfers: [splLeg(TOKEN_ACCOUNT), splLeg(second)],
        accounts: new Map([
          [TOKEN_ACCOUNT, tokenAccount(STRANGER)],
          [second, tokenAccount(other)],
        ]),
      }),
    ).rejects.toMatchObject({ code: "RING_ANONYMOUS_EXIT_DESTINATIONS_DIFFER" });
  });

  const token2022 = (
    tail: readonly number[],
    edit: (data: Uint8Array) => void = () => undefined,
  ): RpcAccount => {
    const base = tokenAccount(STRANGER);
    const data = Uint8Array.from([...base.data, ...tail]);
    edit(data);
    return { ...base, owner: SPL_TOKEN_2022_PROGRAM_ID, data };
  };

  it("reads a Token-2022 account with extensions as SPP unpacks it", async () => {
    // Account type `Account`, then an ImmutableOwner entry of type 7 and length 0.
    await expect(tokenOwnerOf(token2022([2, 7, 0, 0, 0]))).resolves.toBe(STRANGER);
  });

  it.each<readonly [string, RpcAccount, string]>([
    [
      "an extension tail that is not an account",
      token2022([1, 7, 0, 0, 0]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "the multisig length",
      token2022([2, ...new Uint8Array(189)]),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a frozen state",
      token2022([], (data) => (data[108] = AccountState.Frozen)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID",
    ],
    [
      "a delegate tag above one",
      token2022([], (data) => (data[72] = 2)),
      "RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED",
    ],
  ])("refuses a token account with %s", async (_, account, code) => {
    await expect(tokenOwnerOf(account)).rejects.toThrow(
      ringError(code, { destination: TOKEN_ACCOUNT }),
    );
  });

  it("refuses a destination of another program than the token programs", async () => {
    await expect(
      tokenOwnerOf({ ...tokenAccount(STRANGER), owner: randomAddress() }),
    ).rejects.toThrow(
      ringError("RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID", { destination: TOKEN_ACCOUNT }),
    );
  });
});

describe("anonymous rail on a policy ring", () => {
  const ZERO = new Uint8Array(32) as Bytes32;

  /** One rule over the sender's allow list and one SOL limit, the sender's record on the list. */
  function policyRing(
    sender: Sender,
    limit: Readonly<{ cap: bigint; cosignAbove: bigint }>,
    coSigner?: Address,
  ): Promise<Fixture> {
    return anonymousRing({
      table: buildRuleTable({
        rules: [
          {
            subject: "sender",
            source: { kind: "lists", present: [ListId.allow], absent: [] },
            guard: { kind: "always" },
          },
        ],
        limits: [{ asset: memberOfAsset(SOL_MINT), ...limit }],
      }),
      records: [
        {
          member: memberOfIdentity(
            sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
          ),
          lists: 1n,
        },
      ],
      ...(coSigner === undefined
        ? {}
        : { coSigner: { signer: coSigner, scope: RING_COSIGN_TRANSFERS, thresholds: [] } }),
    });
  }

  async function pay(fixture: Fixture, sender: Sender): Promise<ProvenRingTransfer> {
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer: spend(fixture, sender) })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  function memberPolicy(fixture: Fixture) {
    const policy = fixture.ringRequests.find((request) => request.kind === "memberPolicy");
    if (policy?.kind !== "memberPolicy") throw new Error("no member policy request");
    return policy;
  }

  it("proves the policy over the hidden sender's commitment the frame and both statements bind", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 1_000n, cosignAbove: 0n });
    const proven = await pay(fixture, sender);
    const { instruction, data, call } = await expanded(fixture, proven, "anonymous");

    const senderPkHash = sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash();
    const commitment = senderCommitment({
      senderPkHash,
      privateTxBlinding: call.proofInputs.privateTxBlinding(),
    });
    expect(data.policy?.senderCommitment).toEqual(commitment);
    expect(data.approvalRequired).toBe(false);
    const policy = memberPolicy(fixture);
    expect(policy).toMatchObject({ anonymous: true, sender: commitment, senderPkHash });
    expect(policy.senderEntry.own?.kind).toBe("present");
    const registryAccount = fixture.accounts.get(
      await ringMemberRegistryAddress(fixture.ringProgramId),
    );
    if (registryAccount === undefined) throw new Error("no registry");
    const slots = publicSlots(call.proofInputs.externalData.interfaceTransfers);
    expect(policy.publicInputHash).toEqual(
      policyStatementHash({
        withdrawalHash: policyWithdrawalHash([]),
        key: { kind: "member", anonymous: true },
        privateTxHash: data.privateTxHash,
        policyHash: decodeRingMemberRegistry(registryAccount.data).policyHash,
        ringId: ringIdField(fixture.ringProgramId),
        approvalRequired: false,
        keyEscrow: false,
        ownRoot: fixture.ownTree.root,
        curatorRoot: ZERO,
        sender: commitment,
        publicAssets: slots.assets,
        publicAmounts: publicAmountFields(slots),
      }),
    );
    checkAudit(fixture, data, { kind: "anonymousAudit", epoch: EPOCH });
    expect(anonymousAudit(fixture).audit.senderCommitment).toEqual(commitment);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [
        {
          address: await ringMemberRegistryAddress(fixture.ringProgramId),
          role: AccountRole.READONLY,
        },
      ],
      payer: fixture.authority,
    });
  });

  it("refuses a hidden sender off the required list before any proof", async () => {
    const fixture = await policyRing(anonymousSender(), { cap: 1_000n, cosignAbove: 0n });
    await expect(pay(fixture, anonymousSender())).rejects.toThrow(
      ringError("RING_POLICY_RULE_UNSATISFIED", {
        reason: "lists",
        ruleIndex: 0,
        subject: "sender",
      }),
    );
    noProofs(fixture);
  });

  it("refuses an outflow past the cap before any proof", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 399n, cosignAbove: 0n });
    await expect(pay(fixture, sender)).rejects.toThrow(
      ringError("RING_OUTFLOW_CAP_EXCEEDED", { cap: "399", outflow: "400" }),
    );
    noProofs(fixture);
  });

  it("names and signs with the co-signer when the outflow passes the co-sign bound", async () => {
    const sender = anonymousSender();
    const coSigner = randomAddress();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n }, coSigner);
    const proven = await pay(fixture, sender);
    const { instruction, data } = await expanded(fixture, proven, "anonymous");

    expect(proven.approvalRequired).toBe(true);
    expect(proven.coSigner).toBe(coSigner);
    expect(data.approvalRequired).toBe(true);
    expect(memberPolicy(fixture).approvalRequired).toBe(true);
    await checkAccounts(instruction, {
      fixture,
      data,
      prefix: [
        {
          address: await ringMemberRegistryAddress(fixture.ringProgramId),
          role: AccountRole.READONLY,
        },
        { address: coSigner, role: AccountRole.READONLY_SIGNER },
      ],
      payer: fixture.authority,
    });
  });

  it("refuses an outflow past the co-sign bound on a ring without a co-signer", async () => {
    const sender = anonymousSender();
    const fixture = await policyRing(sender, { cap: 0n, cosignAbove: 100n });
    await expect(pay(fixture, sender)).rejects.toThrow(ringError("RING_COSIGNER_REQUIRED"));
    noProofs(fixture);
  });
});

describe("anonymous entry key bound", () => {
  /** A payment out of `count` default-ring notes of the sender. */
  async function entry(
    fixture: Fixture,
    sender: Sender,
    count: number,
  ): Promise<ProvenRingTransfer> {
    const transfer = new ConfidentialTransfer(
      sender.keypair.shieldedAddress(),
      Array.from({ length: count }, () => noteInput(sender.keypair, 1_000n)),
      fixture.authority,
    );
    const to = await addressOf(fixture, ShieldedKeypair.generate());
    return rail({ fixture, sender, transfer })
      .withPayment({ to, asset: SOL_MINT, amount: 400n })
      .prove(fixture.client);
  }

  it("spends eight default-ring notes under the entry key", async () => {
    const fixture = await anonymousRing();
    const proven = await entry(fixture, anonymousSender(), 8);
    const { data } = await expanded(fixture, proven, "anonymous");
    expect(data.fullOpenings).toBe(true);
    expect(data.nullifiers).toHaveLength(8);
    expect(anonymousAudit(fixture).circuit).toBe("custom-ring-audit-anonymous-entry-v2-8-2");
  });

  it("refuses a ninth default-ring note before any proof", async () => {
    const fixture = await anonymousRing();
    await expect(entry(fixture, anonymousSender(), 9)).rejects.toThrow(
      ringError("RING_TRANSACT_DATA_INVALID", { reason: "RingShapeUnkeyed" }),
    );
    noProofs(fixture);
  });
});

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}
