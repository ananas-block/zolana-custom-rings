/** Ring notes and ring deposits opened into a wallet, the pinned zolana sync drops them, Rust `zolana_ring_client::confidential`. */
import { syncWallet, WalletError, type SyncReport, type SyncWalletInput } from "@heliuslabs/zolana";
import type { IndexerReader } from "@heliuslabs/zolana/client";
import {
  bytesKey,
  equalBytes,
  fetchSplAssetRegistrations,
  createIndexerRpcConfig,
  isCanonicalField,
  PAGE_LIMIT,
  ZERO_NULLIFIER_PK,
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
import { registeredMint, spendingTransactions } from "../operations/workflow/recover.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { isRingKeys, type RingKeys, type RingTagFrame } from "./ring-keys.js";
import { isSmallOrder } from "../crypto/keys/x25519.js";
import { decoded, openRingDeposit, type RingDepositNote } from "./ring-deposit.js";
import { answered, exactlyOne, unseen } from "./batch.js";
import { zeroKeyNullifier } from "./exposed-notes.js";
import { openZeroKeyMerges } from "./zero-key-merge.js";
import { HalvingPageLimit, nextHistoryToken } from "../rpc/history.js";

export interface RingNotes {
  readonly utxos: readonly WalletUtxo[];
  /** Slots sent to a held key that no registered mint rebuilds, the caller registers mints and opens again. */
  readonly pending: number;
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
  const deposits = await ringDeposits(input, context);
  const notes = deposits.notes;
  let pending = deposits.pending;
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
      if (opened === PENDING) pending += 1;
      else if (opened !== undefined) notes.push(opened);
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
  return Object.freeze({
    utxos: Object.freeze(
      notes.map((note) => {
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
      }),
    ),
    pending,
  });
}

/** Notes and scan positions commit together after every ring read succeeds. */
export async function syncRingWallet(
  input: SyncWalletInput & Readonly<{ client: RingSyncClient }>,
  context?: RequestContext,
): Promise<SyncReport> {
  return input.wallet._withSyncLock(async () => {
    const { wallet, keys, client } = input;
    const revision = wallet._revision;
    const staging = stageRingHistory(wallet);
    const initialHashes = new Set(
      staging.utxos().map((entry) => bytesKey(entry.outputContext.hash)),
    );
    const pages = new RingSyncPages(input);
    const report = await syncWallet({ ...input, wallet: staging, client: pages.client }, context);
    const open = () =>
      openRingNotes({ keys, assets: staging.registry, transactions: pages.transactions }, context);
    let notes = await open();
    const { solanaRpc, commitment } = client;
    if (notes.pending > 0 && solanaRpc !== undefined && commitment !== undefined) {
      for (const { assetId, mint } of await fetchSplAssetRegistrations(
        { solanaRpc, commitment },
        context,
      ))
        staging.ensureAsset(assetId, mint);
      notes = await open();
    }
    if (notes.pending > 0) throw new WalletError("WALLET_UNRESOLVED_ASSET");

    const state = staging._state();
    const held = new Set(state.utxos.map((entry) => bytesKey(entry.outputContext.hash)));
    const unheld = (entry: WalletUtxo): boolean => unseen(held, bytesKey(entry.outputContext.hash));
    const fresh = notes.utxos.filter(unheld);
    if (isRingKeys(keys))
      fresh.push(
        ...(
          await zeroKeyMergeNotes(
            {
              keys,
              client: pages.client,
              owner: keys.address(),
              pageLimit: input.config?.pageLimit ?? Number(PAGE_LIMIT),
            },
            context,
          )
        ).filter(unheld),
      );
    const owner = keys.address();
    const budget = { remaining: Number.MAX_SAFE_INTEGER };
    const chunkSize = input.config?.queryChunk ?? 64;
    for (let frontier = fresh; frontier.length > 0;) {
      const spends: IndexedShieldedTransaction[] = [];
      for (let offset = 0; offset < frontier.length; offset += chunkSize)
        spends.push(
          ...(await spendingTransactions(
            pages.client,
            frontier.slice(offset, offset + chunkSize).map((entry) => entry.nullifier),
            budget,
            context,
          )),
        );
      const merged = await openRingMerges(
        { keys, owner, assets: staging.registry, spends },
        context,
      );
      frontier = merged.utxos.filter(unheld);
      fresh.push(...frontier);
    }
    const nullifiers = new Set(state.nullifiers);
    for (const transaction of pages.transactions)
      for (const nullifier of transaction.nullifiers) nullifiers.add(bytesKey(nullifier));
    const utxos = [...state.utxos, ...fresh].map((entry) => ({
      ...entry,
      spent: entry.spent || nullifiers.has(bytesKey(entry.nullifier)),
    }));
    wallet._commitSync(
      {
        ...staging._state(),
        utxos,
        nullifiers,
        lastSynced: staging.lastSynced,
        checkpoints: {
          transactions: new Map(staging._checkpointEntries("transactions")),
          proofless: new Map(staging._checkpointEntries("proofless")),
          nullifiers: new Map(staging._checkpointEntries("nullifiers")),
        },
        registryAdditions: staging.registry.entries().map(([assetId, mint]) => ({ assetId, mint })),
      },
      revision,
    );
    return Object.freeze({
      ...report,
      storedUtxos: utxos.filter((entry) => !initialHashes.has(bytesKey(entry.outputContext.hash)))
        .length,
    });
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

const PENDING = Symbol("pending");

/** Tagged by the owner's identity, the tag read covers every ring the wallet holds notes on. */
async function zeroKeyMergeNotes(
  input: Readonly<{
    keys: RingKeys;
    client: Pick<RingSyncClient, "getShieldedTransactionsByTags">;
    owner: ShieldedAddress;
    pageLimit: number;
  }>,
  context: RequestContext | undefined,
): Promise<readonly WalletUtxo[]> {
  const tag = input.owner.signingPublicKey.ownerProofInputHash();
  const rows: IndexedShieldedTransaction[] = [];
  const pageLimit = new HalvingPageLimit(input.pageLimit);
  let token: string | undefined;
  for (;;) {
    const asked = token === undefined ? {} : { paginationToken: token };
    const page = await pageLimit.read((limit) =>
      input.client.getShieldedTransactionsByTags(
        { tags: [tag], limit, ...asked },
        undefined,
        context,
      ),
    );
    rows.push(...page.data.flatMap((item) => item.events));
    const next = nextHistoryToken(token, page);
    if (next === undefined) break;
    token = next;
  }
  const opened = await openZeroKeyMerges({ keys: input.keys, owner: input.owner, rows }, context);
  return opened.map(({ utxo }) => utxo);
}

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

/** Deposits of any ring, Rust `DepositOpener::open_held`, one of an unregistered mint is pending. */
async function ringDeposits(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context: RequestContext | undefined,
): Promise<Readonly<{ notes: Note[]; pending: number }>> {
  const owner = input.keys.address();
  const held = input.keys.viewingPublicKeys();
  const notes: Note[] = [];
  let pending = 0;
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
      if (registeredMint(input.assets, opened.utxo.asset) === undefined) pending += 1;
      else notes.push({ ...opened, utxoHash: slot.outputContext.hash, slot });
    }
  return { notes, pending };
}

/** `undefined` for a slot sent to no held key. */
async function openSlot(
  input: Readonly<{ keys: ShieldedKeys; assets: AssetRegistry }>,
  site: Site,
  context: RequestContext | undefined,
): Promise<Note | typeof PENDING | undefined> {
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
): Promise<Note | typeof PENDING | undefined> {
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
    if (!note.registered) return PENDING;
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

function stageRingHistory(wallet: Wallet): Wallet {
  // Core tag checkpoints can cover unopened ring bodies.
  const staging = new Wallet({ identity: wallet.identity, registry: wallet.registry });
  staging._replace({ ...wallet._state(), lastSynced: wallet.lastSynced });
  for (const [key, slot] of wallet._checkpointEntries("nullifiers"))
    staging._setSyncCheckpoint("nullifiers", key, slot);
  return staging;
}

class RingSyncPages {
  readonly transactions: IndexedShieldedTransaction[] = [];
  readonly client: RingSyncClient;

  constructor(input: SyncWalletInput & Readonly<{ client: RingSyncClient }>) {
    const { client, config } = input;
    const fallback = createIndexerRpcConfig(
      config?.retry ?? client.indexerConfig?.poll,
      config?.requireSlot ?? client.indexerConfig?.requireSlot,
    );
    const limit = config?.pageLimit ?? 1_000;
    const held = input.keys.viewingPublicKeys();
    // The core sync names a held key whole, a delivered slot publishes its slot tag.
    const withSlotTags = (tags: readonly Bytes32[]): readonly Bytes32[] =>
      tags.flatMap((tag) => {
        const key = held.find((candidate) => equalBytes(candidate.u(), tag));
        return key === undefined ? [tag] : [tag, confidentialSlotTag(key.u())];
      });
    this.client = {
      ...(client.solanaRpc === undefined ? {} : { solanaRpc: client.solanaRpc }),
      ...(client.commitment === undefined ? {} : { commitment: client.commitment }),
      ...(client.indexerConfig === undefined ? {} : { indexerConfig: client.indexerConfig }),
      getEncryptedUtxosByTags: async (request, rpcConfig, context) => {
        const page = await client.getEncryptedUtxosByTags(request, rpcConfig, context);
        for (const match of page.data.flatMap((item) => item.outputs)) {
          if (match.txViewingPk !== undefined || match.salt !== undefined) continue;
          this.transactions.push({
            slot: match.slot,
            txSignature: match.txSignature,
            outputSlots: [match.outputSlot],
            messages: [],
            nullifiers: [],
            proofless: true,
          });
        }
        return page;
      },
      getShieldedTransactionsByTags: async (request, rpcConfig, context) => {
        const page = await client.getShieldedTransactionsByTags(
          { ...request, tags: withSlotTags(request.tags) },
          rpcConfig,
          context,
        );
        this.transactions.push(...page.data.flatMap((item) => item.events));
        return page;
      },
      getShieldedTransactionsByNullifiers: async (request, rpcConfig, context) => {
        const page = await client.getShieldedTransactionsByNullifiers(
          { limit, ...request },
          rpcConfig ?? fallback,
          context,
        );
        this.transactions.push(...page.data.flatMap((item) => item.events));
        return page;
      },
    };
  }
}
