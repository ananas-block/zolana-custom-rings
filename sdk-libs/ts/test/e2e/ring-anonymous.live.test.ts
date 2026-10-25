// Fresh anonymous rings keyed by the harness ring rpc in derived mode, one admitting listed senders only.
import { generateKeyPairSigner, type KeyPairSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { syncWallet } from "@heliuslabs/zolana";
import {
  ListId,
  buildRuleTable,
  memberOfIdentity,
  recordBit,
  type RuleTable,
} from "../../src/ring/advanced.js";
import { customRingDepositPayload } from "../../src/protocol/transaction/deposit-payload.js";
import {
  AuthorityListWrite,
  RingInstructionTag,
  buildRingDepositTransaction,
  buildRingTransferTransaction,
  fetchRingProgramConfig,
  listWrite,
  messageSignerSpendSigner,
  ringComputeUnitLimit,
} from "../../src/ring/index.js";
import { currentSlot, signSendAndConfirm, type Actor } from "./live-helpers.js";
import {
  airdrop,
  auditedRingAmounts,
  freshActor,
  indexedKeys,
  indexedRecord,
  readableRing,
  ringHoldings,
  sendInstruction,
  waitForAudited,
  type ReadableRing,
} from "./ring-live-helpers.js";
import { AnonymousRingState } from "../../src/state/anonymous-state.js";
import { LocalRingKeys, ringWalletKeys } from "../../src/state/ring-keys.js";
import { issueRingAddress } from "../../src/state/anonymous.js";

const DEPOSIT = 1_000_000_000n;
const PAYMENT = 250_000_000n;

interface AnonymousRing extends ReadableRing {
  readonly creationEpoch: bigint;
  /** Pays every fee, an anonymous ring refuses a signer holding the hidden owner's key. */
  readonly funder: KeyPairSigner;
}

async function anonymousRing(
  kind: Readonly<{ kind: "anonymous" }> | Readonly<{ kind: "anonymousPolicy"; table: RuleTable }>,
): Promise<AnonymousRing> {
  const ring = await readableRing(kind);
  const funder = await generateKeyPairSigner();
  await airdrop(ring.client, funder.address);
  const { creationEpoch } = await fetchRingProgramConfig(ring.client, ring.ringProgramId);
  return { ...ring, creationEpoch, funder };
}

/** The ring rpc names the hidden sender and opens the payment and its change. */
async function expectAudited(ring: AnonymousRing, sender: Actor, signature: string): Promise<void> {
  const item = await waitForAudited(ring.ringRpc, ring.target, ring.authority, signature);
  expect(item.sender?.ownerKey).toEqual(sender.keypair.signingPublicKey().ed25519());
  expect(item.payloadErrors).toEqual([]);
  expect(auditedRingAmounts(item)).toEqual([PAYMENT, DEPOSIT - PAYMENT]);
}

/** Reads every stream of the ring through the current slot. */
async function syncRing(ring: AnonymousRing, actor: Actor): Promise<void> {
  const slot = await currentSlot(ring.client);
  await syncWallet({
    client: ring.client,
    wallet: actor.wallet,
    keys: actor.keys,
    config: { depositPayloadDecoder: customRingDepositPayload, requireSlot: slot },
  });
}

/** A member whose own deposit funds its hidden identity on the ring. */
async function depositor(ring: AnonymousRing): Promise<Actor> {
  const sender = await freshActor(ring.client);
  const deposit = await buildRingDepositTransaction({
    client: ring.client,
    ringProgramId: ring.ringProgramId,
    feePayer: ring.funder.address,
    recipient: {
      kind: "anonymous",
      keys: LocalRingKeys.fromKeypair(sender.keypair),
      state: AnonymousRingState.create(ring.ringProgramId, ring.creationEpoch),
    },
    amount: DEPOSIT,
  });
  await signSendAndConfirm(ring.client, deposit, [ring.funder]);
  await syncRing(ring, sender);
  expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT);
  return sender;
}

/** The hidden owner signs inside the proof, the funder pays and signs the transaction. */
async function payment(ring: AnonymousRing, sender: Actor, recipient: Actor) {
  const { address: to } = await issueRingAddress({
    state: AnonymousRingState.create(ring.ringProgramId, ring.creationEpoch),
    keys: LocalRingKeys.fromKeypair(recipient.keypair),
  });
  const state = AnonymousRingState.create(ring.ringProgramId, ring.creationEpoch);
  return async () =>
    buildRingTransferTransaction({
      client: ring.client,
      ringProgramId: ring.ringProgramId,
      wallet: sender.wallet,
      keys: ringWalletKeys(sender.keys, LocalRingKeys.fromKeypair(sender.keypair)),
      feePayer: ring.funder.address,
      recipient: to,
      amount: PAYMENT,
      anonymous: { signer: messageSignerSpendSigner(sender.signer), state },
    });
}

// The pinned zolana TS lacks the anonymous ring prover and stream scan.
describe.skip("anonymous ring", () => {
  it("pays a ring address end to end, the recipient and the sender's change found by sync", async () => {
    const ring = await anonymousRing({ kind: "anonymous" });
    const sender = await depositor(ring);
    const recipient = await freshActor(ring.client);
    const pay = await payment(ring, sender, recipient);
    const signature = await signSendAndConfirm(ring.client, await pay(), [ring.funder]);
    await expectAudited(ring, sender, signature);
    await syncRing(ring, recipient);
    expect(ringHoldings(recipient, ring.ringProgramId)).toBe(PAYMENT);
    await syncRing(ring, sender);
    expect(ringHoldings(sender, ring.ringProgramId)).toBe(DEPOSIT - PAYMENT);
  }, 900_000);

  it("refuses an unlisted hidden sender before any proof and pays once the authority lists it", async () => {
    const ring = await anonymousRing({
      kind: "anonymousPolicy",
      table: buildRuleTable({
        rules: [
          {
            subject: "sender",
            source: { kind: "lists", present: [ListId.allow], absent: [] },
            guard: { kind: "always" },
          },
        ],
      }),
    });
    const sender = await depositor(ring);
    const recipient = await freshActor(ring.client);
    const pay = await payment(ring, sender, recipient);
    await expect(pay()).rejects.toMatchObject({
      code: "RING_BUILD_TRANSFER",
      causeCode: "RING_POLICY_RULE_UNSATISFIED",
    });

    const member = memberOfIdentity(
      sender.keypair.shieldedAddress().signingPublicKey.ownerProofInputHash(),
    );
    const listed = await new AuthorityListWrite({
      ringProgramId: ring.ringProgramId,
      authority: ring.authority.address,
    })
      .withWrite(member, listWrite({ set: [ListId.allow] }))
      .prove(ring.client);
    await sendInstruction(
      ring.client,
      listed.instruction,
      ring.authority,
      ringComputeUnitLimit(RingInstructionTag.authorityWriteRecords),
    );
    // The policy reads the record Photon serves, the indexer lags the chain.
    for (let attempt = 0; ; attempt++) {
      const read = await indexedKeys(() => indexedRecord(ring.client, ring.ringProgramId, member));
      if (((read.record?.lists ?? 0n) & recordBit(ListId.allow)) !== 0n) break;
      if (attempt === 240) throw new Error("the allow list write was not indexed");
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
    const signature = await signSendAndConfirm(ring.client, await pay(), [ring.funder]);
    await expectAudited(ring, sender, signature);
    await syncRing(ring, recipient);
    expect(ringHoldings(recipient, ring.ringProgramId)).toBe(PAYMENT);
  }, 900_000);
});
