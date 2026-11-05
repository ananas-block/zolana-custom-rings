/**
 * Ring notes and ring deposits opened into a wallet, the pinned zolana sync drops them, Rust `zolana_ring_client::confidential`.
 *
 * Read `syncRingWallet` first. Each ring tag keeps its own cursor beside the core sync's checkpoints, `RingWallet._absorb` stores both with the notes.
 */
import { syncWallet, type SyncReport, type SyncWalletInput } from "@heliuslabs/zolana";
import type { IndexerReader, IndexerRpcConfig } from "@heliuslabs/zolana/client";
import {
  bytesKey,
  equalBytes,
  fetchSplAssetRegistrations,
  createIndexerRpcConfig,
  isCanonicalField,
  ZERO_NULLIFIER_PK,
  type CheckpointStream,
  type SyncCheckpointAdvances,
} from "@heliuslabs/zolana/internal";
import { confidentialSlotTag } from "../crypto/derivation/ring-stream.js";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { ShieldedAddress, X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  decryptTransactions,
  Wallet,
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type ShieldedKeys,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { ringBodyOutput, readRingOutput, RingScheme } from "../protocol/transaction/output.js";
import { openRecipientNote } from "../crypto/derivation/blinding.js";
import { openRecipientBody } from "../protocol/codec/anonymous-delivery.js";
import { customRingDepositPayload } from "../protocol/transaction/deposit-payload.js";
import { spendingTransactions } from "../operations/workflow/recover.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { isRingKeys, type RingKeys, type RingTagFrame } from "./ring-keys.js";
import { isSmallOrder } from "../crypto/keys/x25519.js";
import { decoded, openRingDeposit, type RingDepositNote } from "./ring-deposit.js";
import { answered, exactlyOne, unseen } from "./batch.js";
import { zeroKeyNullifier } from "./exposed-notes.js";
import { openZeroKeyMerges } from "./zero-key-merge.js";
import { HalvingPageLimit, nextHistoryToken } from "../rpc/history.js";
import { isPendingNote, type RingWallet } from "./ring-wallet.js";

export interface RingNotes {
  readonly utxos: readonly WalletUtxo[];
  /** Notes sent to a held key under a mint the registry lacks, a transfer never selects one. */
  readonly pendingOpenings: readonly WalletUtxo[];
}

/** Every note is unspent, a ring body opens only under keys that are also `RingKeys`, a malformed audit capsule skips its deposit. */
export async function openRingNotes(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context?: RequestContext,
): Promise<RingNotes> {
  const notes = await ringDeposits(input, context);
  for (const tx of input.transactions) {
    const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
    if (ring === undefined || txViewingPublicKey === undefined || salt === undefined) continue;
    for (const [slotIndex, slot] of tx.outputSlots.entries()) {
      const site: Site = {
        tx,
        ring,
        txViewingPublicKey,
        salt,
        slotIndex,
        slot,
      };
      const opened = await openSlot(input, site, context);
      if (opened !== undefined) notes.push(opened);
    }
  }
  const keyed = notes.filter(
    ({ nullifierPublicKey }) => !equalBytes(nullifierPublicKey, ZERO_NULLIFIER_PK),
  );
  const derived =
    keyed.length === 0
      ? []
      : await input.keys.derive(
          keyed.map(({ utxo, utxoHash }) => ({
            kind: "nullifier",
            utxoHash,
            blinding: utxo.blinding,
          })),
          context,
        );
  const nullifiers = new Map(answered(keyed, derived));
  const opened = notes.map((note): WalletUtxo => {
    const { utxoHash, slot, nullifierPublicKey: _key, ...fields } = note;
    return Object.freeze({
      ...fields,
      outputContext: Object.freeze({
        hash: utxoHash,
        tree: slot.outputContext.tree,
        leafIndex: slot.outputContext.leafIndex,
      }),
      nullifier: nullifiers.get(note) ?? zeroKeyNullifier(utxoHash, note.utxo.blinding),
      spent: false,
    });
  });
  return Object.freeze({
    utxos: Object.freeze(opened.filter((note) => !isPendingNote(input.assets, note))),
    pendingOpenings: Object.freeze(opened.filter((note) => isPendingNote(input.assets, note))),
  });
}

export type RingSyncInput = Omit<SyncWalletInput, "wallet"> &
  Readonly<{ wallet: RingWallet; client: RingSyncClient }>;

/** Notes, pending notes and every scan cursor commit together after every read succeeds. */
export async function syncRingWallet(
  input: RingSyncInput,
  context?: RequestContext,
): Promise<SyncReport> {
  const { wallet: ring, keys, client } = input;
  const { wallet } = ring;
  return wallet._withSyncLock(async () => {
    const revision = wallet._revision;
    // 1. The core sync resumes from its checkpoints on a copy, nothing reaches the wallet before step 5.
    const staging = wallet._clone();
    const reads = new RingReads(input, staging, context);
    const report = await syncWallet({ ...input, wallet: staging, client: reads.client }, context);
    // 2. Ring outputs publish tags the core sync never reads, each tag resumes at its own cursor.
    const opened = await openRingNotes(
      { keys, assets: staging.registry, transactions: await reads.deliveries() },
      context,
    );
    const notes = [...opened.utxos, ...opened.pendingOpenings];
    if (isRingKeys(keys)) notes.push(...(await reads.zeroKeyMerges(keys)));
    // 3. One registry refresh per sync, a note the refresh leaves unnamed is stored pending and its cursor still advances.
    const { solanaRpc, commitment } = client;
    if (
      [...notes, ...ring.pendingOpenings()].some((note) => isPendingNote(staging.registry, note)) &&
      solanaRpc !== undefined &&
      commitment !== undefined
    )
      for (const { assetId, mint } of await fetchSplAssetRegistrations(
        { solanaRpc, commitment },
        context,
      ))
        staging.ensureAsset(assetId, mint);
    // 4. A note new to the wallet or promoted now has unread spends, a merge folding it opens another.
    const held = new Set(
      [...staging.utxos(), ...ring.pendingOpenings()].map((note) =>
        bytesKey(note.outputContext.hash),
      ),
    );
    const fresh = notes.filter((note) => unseen(held, bytesKey(note.outputContext.hash)));
    const promoted = ring
      .pendingOpenings()
      .filter((note) => !isPendingNote(staging.registry, note));
    const owner = keys.address();
    const budget = { remaining: Number.MAX_SAFE_INTEGER };
    const chunkSize = input.config?.queryChunk ?? 64;
    for (let frontier = [...fresh, ...promoted]; frontier.length > 0;) {
      const spends: IndexedShieldedTransaction[] = [];
      for (let offset = 0; offset < frontier.length; offset += chunkSize)
        spends.push(
          ...(await spendingTransactions(
            reads.client,
            frontier.slice(offset, offset + chunkSize).map((entry) => entry.nullifier),
            budget,
            context,
          )),
        );
      const merged = await openRingMerges(
        { keys, owner, assets: staging.registry, spends },
        context,
      );
      frontier = merged.utxos.filter((note) => unseen(held, bytesKey(note.outputContext.hash)));
      fresh.push(...frontier);
    }
    // 5. The core rows, the ring notes and every cursor land in one commit.
    const initial = new Set(wallet.utxos().map((note) => bytesKey(note.outputContext.hash)));
    let storedUtxos = 0;
    ring._absorb({ notes: fresh, spentNullifiers: reads.spentNullifiers() }, staging, (commit) => {
      wallet._commitSync(
        {
          ...staging._state(),
          ...commit,
          lastSynced: staging.lastSynced,
          checkpoints: reads.checkpoints(),
          registryAdditions: staging.registry
            .entries()
            .map(([assetId, mint]) => ({ assetId, mint })),
        },
        revision,
      );
      storedUtxos = commit.utxos.filter(
        (note) => !initial.has(bytesKey(note.outputContext.hash)),
      ).length;
    });
    return Object.freeze({ ...report, storedUtxos });
  });
}

export type RingSyncClient = SyncWalletInput["client"] &
  Pick<IndexerReader, "getShieldedTransactionsByNullifiers" | "getShieldedTransactionsByTags">;

interface Site {
  readonly tx: IndexedShieldedTransaction;
  readonly ring: NonNullable<IndexedShieldedTransaction["ringProgramId"]>;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: NonNullable<IndexedShieldedTransaction["salt"]>;
  readonly slotIndex: number;
  readonly slot: IndexedShieldedTransaction["outputSlots"][number];
}

type Note = RingDepositNote & Readonly<{ utxoHash: Bytes32 }> & Readonly<{ slot: Site["slot"] }>;

/** The ring merges among `spends` and the notes they open to `owner`, Rust `RingMerges`. */
/** A merge publishes no transaction key or salt, a deposit no proof. */
export function isRingMergeRow(tx: IndexedShieldedTransaction): boolean {
  return (
    tx.ringProgramId !== undefined &&
    !tx.proofless &&
    tx.txViewingPublicKey === undefined &&
    tx.salt === undefined
  );
}

export async function openRingMerges(
  input: Readonly<{
    keys: ShieldedKeys;
    owner: ShieldedAddress;
    assets: AssetRegistry;
    spends: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<
  Readonly<{
    merges: readonly IndexedShieldedTransaction[];
    utxos: readonly WalletUtxo[];
  }>
> {
  const merges = input.spends.filter(isRingMergeRow);
  if (merges.length === 0) return { merges, utxos: [] };
  const opened = new Wallet({ identity: input.owner, registry: input.assets });
  await decryptTransactions({
    wallet: opened,
    keys: input.keys,
    transactions: merges,
    context,
  });
  return { merges, utxos: opened._state().utxos };
}

/** Deposits of any ring, Rust `DepositOpener::open_held`. */
async function ringDeposits(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<Note[]> {
  const owner = input.keys.address();
  const held = input.keys.viewingPublicKeys();
  const notes: Note[] = [];
  const seen = new Set<string>();
  for (const tx of input.transactions)
    for (const slot of tx.outputSlots) {
      const viewingPublicKey = held.find((key) => equalBytes(key.u(), slot.viewTag));
      if (viewingPublicKey === undefined || seen.has(bytesKey(slot.outputContext.hash))) continue;
      const opened = await openRingDeposit(
        {
          keys: input.keys,
          owner,
          viewingPublicKey,
          outputSlot: slot,
          depositPayload: customRingDepositPayload,
        },
        context,
      );
      if (opened === undefined) continue;
      seen.add(bytesKey(slot.outputContext.hash));
      notes.push({ ...opened, utxoHash: slot.outputContext.hash, slot });
    }
  return notes;
}

/** `undefined` for a slot sent to no held key. */
async function openSlot(
  input: Readonly<{ keys: ShieldedKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | undefined> {
  let frame: ReturnType<typeof readRingOutput>;
  try {
    frame = readRingOutput(site.slot.payload);
  } catch {
    return undefined;
  }
  if (frame.encoding !== "encrypted") return undefined;
  if (!isRingKeys(input.keys)) return undefined;
  const reads = { keys: input.keys, assets: input.assets };
  return frame.scheme === RingScheme.ringBody ? recipientNote(reads, site, context) : undefined;
}

/** The body names its mint, a commitment under the wallet's key or zero proves the note. */
async function recipientNote(
  input: Readonly<{ keys: RingKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | undefined> {
  const parts = ringBodyOutput(site.slot.payload);
  if (parts === undefined) return undefined;
  const slotSecret = await heldSlotSecret(input.keys, site, context);
  if (slotSecret === undefined) return undefined;
  const owner = input.keys.address();
  try {
    const note = decoded(() =>
      openRecipientNote(
        {
          owner,
          ring: site.ring,
          treeId: outputTreeId(site.slot.outputContext),
          commitment: site.slot.outputContext.hash,
          assets: input.assets,
        },
        openRecipientBody(slotSecret, parts.body),
      ),
    );
    if (note === undefined) return undefined;
    const { registered: _registered, ...opened } = note;
    return Object.freeze({ ...opened, slot: site.slot });
  } finally {
    slotSecret.fill(0);
  }
}

/** Malformed published bytes skip the slot, a holder failure refuses the sync. */
async function heldSlotSecret(
  keys: RingKeys,
  site: Site,
  context: RequestContext | undefined,
): Promise<Bytes32 | undefined> {
  // The holder is asked only under the key whose public tag the slot carries.
  const viewingPublicKey = keys
    .viewingPublicKeys()
    .find((key) => equalBytes(confidentialSlotTag(key.u()), site.slot.viewTag));
  const firstNullifier = site.tx.nullifiers[0];
  if (
    viewingPublicKey === undefined ||
    firstNullifier === undefined ||
    isSmallOrder(site.txViewingPublicKey) ||
    !isCanonicalField(firstNullifier)
  )
    return undefined;
  const frame: RingTagFrame = {
    viewingPublicKey,
    txViewingPublicKey: site.txViewingPublicKey,
    salt: site.salt,
    firstNullifier,
    probes: [{ kind: "confidential", outputIndex: site.slotIndex, tag: site.slot.viewTag }],
  };
  const answers = exactlyOne(await keys.ringTagMatches([frame], context));
  return answered(frame.probes, answers)[0]?.[1];
}

/** A ring cursor sits beside the core sync's checkpoints under a key the core sync never names. */
type RingCursorStream = Exclude<CheckpointStream, "nullifiers">;

/** The reads one sync makes, the spends they returned and the cursors they reached. */
class RingReads {
  readonly client: RingSyncClient;
  readonly #keys: ShieldedKeys;
  readonly #staging: Wallet;
  readonly #context: RequestContext | undefined;
  readonly #rpcConfig: IndexerRpcConfig;
  readonly #pageLimit: HalvingPageLimit;
  readonly #spends: IndexedShieldedTransaction[] = [];
  readonly #reached: Record<RingCursorStream, Map<string, bigint>> = {
    transactions: new Map(),
    proofless: new Map(),
  };

  constructor(input: RingSyncInput, staging: Wallet, context: RequestContext | undefined) {
    const { client, config } = input;
    this.#keys = input.keys;
    this.#staging = staging;
    this.#context = context;
    this.#rpcConfig = createIndexerRpcConfig(
      config?.retry ?? client.indexerConfig?.poll,
      config?.requireSlot ?? client.indexerConfig?.requireSlot,
    );
    const limit = config?.pageLimit ?? 1_000;
    this.#pageLimit = new HalvingPageLimit(limit);
    this.client = {
      ...(client.solanaRpc === undefined ? {} : { solanaRpc: client.solanaRpc }),
      ...(client.commitment === undefined ? {} : { commitment: client.commitment }),
      ...(client.indexerConfig === undefined ? {} : { indexerConfig: client.indexerConfig }),
      getEncryptedUtxosByTags: (request, rpcConfig, context) =>
        client.getEncryptedUtxosByTags(request, rpcConfig, context),
      getShieldedTransactionsByTags: (request, rpcConfig, context) =>
        client.getShieldedTransactionsByTags(request, rpcConfig, context),
      // Every spend read, the core sync's and the ring's, marks the notes it names.
      getShieldedTransactionsByNullifiers: async (request, rpcConfig, context) => {
        const page = await client.getShieldedTransactionsByNullifiers(
          { limit, ...request },
          rpcConfig ?? this.#rpcConfig,
          context,
        );
        this.#spends.push(...page.data.flatMap((item) => item.events));
        return page;
      },
    };
  }

  /** Deposits and delivered bodies to each held key above that key's ring cursors. */
  async deliveries(): Promise<readonly IndexedShieldedTransaction[]> {
    const rows: IndexedShieldedTransaction[] = [];
    for (const key of this.#keys.viewingPublicKeys()) {
      const slotTag = confidentialSlotTag(key.u());
      // A deposit names the key itself, the core sync's cursor there can pass a deposit it drops.
      rows.push(...(await this.#read("proofless", slotTag, key.u())));
      // Only ring keys open a body, the cursor waits for a sync that holds them.
      if (isRingKeys(this.#keys))
        rows.push(...(await this.#read("transactions", slotTag, slotTag)));
    }
    return rows;
  }

  /** The owner tag covers every ring, a seed no held key derives leaves the note to `OwnerGrant`. */
  async zeroKeyMerges(keys: RingKeys): Promise<readonly WalletUtxo[]> {
    const owner = keys.address();
    const tag = owner.signingPublicKey.ownerProofInputHash();
    const rows = await this.#read("transactions", tag, tag);
    const opened = await openZeroKeyMerges({ keys, owner, rows }, this.#context);
    return opened.map(({ utxo }) => utxo);
  }

  spentNullifiers(): readonly Bytes32[] {
    return this.#spends.flatMap((transaction) => transaction.nullifiers);
  }

  /** The staged core checkpoints with the ring cursors this sync reached. */
  checkpoints(): SyncCheckpointAdvances {
    const staged = (stream: CheckpointStream) => new Map(this.#staging._checkpointEntries(stream));
    const transactions = staged("transactions");
    const proofless = staged("proofless");
    for (const [key, slot] of this.#reached.transactions) transactions.set(key, slot);
    for (const [key, slot] of this.#reached.proofless) proofless.set(key, slot);
    return { transactions, proofless, nullifiers: staged("nullifiers") };
  }

  /**
   * Every row of `tag` above the cursor under `cursor` on `stream`.
   *
   * The terminal page's snapshot slot covers every match at or below it and becomes the cursor. A page behind the stored cursor never moves it back.
   */
  async #read(
    stream: RingCursorStream,
    cursor: Bytes32,
    tag: Bytes32,
  ): Promise<readonly IndexedShieldedTransaction[]> {
    const key = bytesKey(cursor);
    const after = this.#staging._syncCheckpoint(stream, key);
    const rows: IndexedShieldedTransaction[] = [];
    let token: string | undefined;
    for (;;) {
      const asked = {
        tags: [tag],
        ...(after === undefined ? {} : { filters: { slot: { gt: after } } }),
        ...(token === undefined ? {} : { paginationToken: token }),
      };
      const page =
        stream === "transactions"
          ? await this.#pageLimit.read(async (limit) => {
              const read = await this.client.getShieldedTransactionsByTags(
                { ...asked, limit },
                this.#rpcConfig,
                this.#context,
              );
              rows.push(...read.data.flatMap((item) => item.events));
              return read;
            })
          : await this.#pageLimit.read(async (limit) => {
              const read = await this.client.getEncryptedUtxosByTags(
                { ...asked, limit },
                this.#rpcConfig,
                this.#context,
              );
              rows.push(...prooflessRows(read));
              return read;
            });
      const next = nextHistoryToken(token, page);
      if (next === undefined) {
        const reached = page.context.slot;
        this.#reached[stream].set(key, after !== undefined && after > reached ? after : reached);
        return rows;
      }
      token = next;
    }
  }
}

/** A match carrying a transaction key or salt is a transfer slot, not a deposit. */
function prooflessRows(
  page: Awaited<ReturnType<RingSyncClient["getEncryptedUtxosByTags"]>>,
): readonly IndexedShieldedTransaction[] {
  return page.data
    .flatMap((item) => item.outputs)
    .filter((match) => match.txViewingPk === undefined && match.salt === undefined)
    .map((match) => ({
      slot: match.slot,
      txSignature: match.txSignature,
      outputSlots: [match.outputSlot],
      messages: [],
      nullifiers: [],
      proofless: true,
    }));
}
