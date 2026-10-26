/** Ring notes of scheme 10 opened into a wallet, the pinned zolana sync drops them, Rust `zolana_ring_client::confidential`. */
import { syncWallet, WalletError, type SyncReport, type SyncWalletInput } from "@heliuslabs/zolana";
import type { IndexerReader } from "@heliuslabs/zolana/client";
import { bytesKey, equalBytes, fetchSplAssetRegistrations } from "@heliuslabs/zolana/internal";
import type { Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import type { X25519PublicKey } from "@heliuslabs/zolana/keypair";
import {
  type AssetRegistry,
  type IndexedShieldedTransaction,
  type ShieldedKeys,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { readRingOutput, RingScheme } from "../protocol/transaction/output.js";
import { nextScanCursor } from "../operations/audit/audit.js";
import { openRingDelivery } from "../crypto/derivation/blinding.js";
import { spendingTransactions } from "../operations/workflow/recover.js";
import { outputTreeId } from "../protocol/membership/trees.js";
import { isRingKeys, type RingKeys } from "./ring-keys.js";
import type { RingDeliveredNote } from "../crypto/derivation/blinding.js";

export interface RingNotes {
  readonly utxos: readonly WalletUtxo[];
  /** Slots sent to a held key that no registered mint rebuilds, the caller registers mints and opens again. */
  readonly pending: number;
}

/** Every note is unspent, scheme 10 opens only under keys that are also `RingKeys`. */
export async function openRingNotes(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    transactions: readonly IndexedShieldedTransaction[];
  }>,
  context?: RequestContext,
): Promise<RingNotes> {
  const notes: Note[] = [];
  let pending = 0;
  for (const tx of input.transactions) {
    const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
    if (ring === undefined || txViewingPublicKey === undefined || salt === undefined) continue;
    for (const [slotIndex, slot] of tx.outputSlots.entries()) {
      const site: Site = { tx, ring, txViewingPublicKey, salt, slotIndex, slot };
      const opened = await openSlot(input, site, context);
      if (opened === PENDING) pending += 1;
      else if (opened !== undefined) notes.push(opened);
    }
  }
  const nullifiers =
    notes.length === 0
      ? []
      : await input.keys.derive(
          notes.map(({ utxo, utxoHash }) => ({
            kind: "nullifier",
            utxoHash,
            blinding: utxo.blinding,
          })),
          context,
        );
  if (nullifiers.length !== notes.length) throw new WalletError("WALLET_KEYS_BATCH_MISMATCH");
  return Object.freeze({
    utxos: Object.freeze(
      notes.map(({ utxo, utxoHash, slot }, index) =>
        Object.freeze({
          utxo,
          outputContext: Object.freeze({
            hash: utxoHash,
            tree: slot.outputContext.tree,
            leafIndex: slot.outputContext.leafIndex,
          }),
          nullifier: nullifiers[index] as Bytes32,
          spent: false,
        }),
      ),
    ),
    pending,
  });
}

/** `syncWallet`, then the ring notes it drops, each read spent once a spend of it is indexed. */
export async function syncRingWallet(
  input: SyncWalletInput & Readonly<{ client: RingSyncClient }>,
  context?: RequestContext,
): Promise<SyncReport> {
  const report = await syncWallet(input, context);
  const { wallet, keys, client } = input;
  const transactions = await taggedTransactions(
    client,
    keys.viewingPublicKeys().map((key) => key.u()),
    context,
  );
  const open = () => openRingNotes({ keys, assets: wallet.registry, transactions }, context);
  let notes = await open();
  const { solanaRpc, commitment } = client;
  if (notes.pending > 0 && solanaRpc !== undefined && commitment !== undefined) {
    for (const { assetId, mint } of await fetchSplAssetRegistrations(
      { solanaRpc, commitment },
      context,
    ))
      wallet.ensureAsset(assetId, mint);
    notes = await open();
  }
  await wallet._withSyncLock(async () => {
    const state = wallet._state();
    const held = new Set(state.utxos.map((entry) => bytesKey(entry.outputContext.hash)));
    const fresh = notes.utxos.filter((entry) => !held.has(bytesKey(entry.outputContext.hash)));
    if (fresh.length === 0) return;
    const spends = await spendingTransactions(
      client,
      fresh.map((entry) => entry.nullifier),
      { remaining: Number.MAX_SAFE_INTEGER },
      context,
    );
    const nullifiers = new Set(state.nullifiers);
    for (const spend of [...transactions, ...spends])
      for (const nullifier of spend.nullifiers) nullifiers.add(bytesKey(nullifier));
    wallet._replace({
      ...state,
      utxos: [
        ...state.utxos,
        ...fresh.map((entry) => ({ ...entry, spent: nullifiers.has(bytesKey(entry.nullifier)) })),
      ],
      nullifiers,
    });
  });
  return report;
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

type Note = RingDeliveredNote & Readonly<{ slot: Site["slot"] }>;

const PENDING = Symbol("pending");

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
  if (frame.scheme === RingScheme.ringConfidentialDelivered && isRingKeys(input.keys))
    return deliveredNote({ keys: input.keys, assets: input.assets }, site, frame.body, context);
  return undefined;
}

/** The slot secret keys the body, the asset is the registered mint that rebuilds the commitment. */
async function deliveredNote(
  input: Readonly<{ keys: RingKeys; assets: AssetRegistry }>,
  site: Site,
  body: Uint8Array,
  context: RequestContext | undefined,
): Promise<Note | typeof PENDING | undefined> {
  const viewingPublicKey = input.keys
    .viewingPublicKeys()
    .find((key) => equalBytes(key.u(), site.slot.viewTag));
  const firstNullifier = site.tx.nullifiers[0];
  if (viewingPublicKey === undefined || firstNullifier === undefined) return undefined;
  const slotSecret = await opened(context, async () => {
    const [secret] = await input.keys.ringDeliverySecrets(
      [
        {
          viewingPublicKey,
          txViewingPublicKey: site.txViewingPublicKey,
          salt: site.salt,
          outputIndex: site.slotIndex,
          firstNullifier,
        },
      ],
      context,
    );
    return secret;
  });
  if (slotSecret === undefined) return undefined;
  const owner = input.keys.address();
  const note = openRingDelivery(
    { ring: site.ring },
    {
      body,
      slotSecret,
      owner: {
        signingPublicKey: owner.signingPublicKey,
        nullifierPublicKey: owner.nullifierPublicKey,
      },
      commitment: site.slot.outputContext.hash,
      treeId: outputTreeId(site.slot.outputContext),
    },
    input.assets,
  );
  return note === undefined ? PENDING : Object.freeze({ ...note, slot: site.slot });
}

/** A body that fails to open is another key's or malformed, an abort still stops the sync. */
async function opened<T>(
  context: RequestContext | undefined,
  open: () => Promise<T | undefined>,
): Promise<T | undefined> {
  try {
    return await open();
  } catch (error) {
    if (context?.signal?.aborted === true) throw error;
    return undefined;
  }
}

async function taggedTransactions(
  client: Pick<IndexerReader, "getShieldedTransactionsByTags">,
  tags: readonly Bytes32[],
  context: RequestContext | undefined,
): Promise<readonly IndexedShieldedTransaction[]> {
  const transactions: IndexedShieldedTransaction[] = [];
  let cursor: Uint8Array | undefined;
  for (;;) {
    const page = await client.getShieldedTransactionsByTags(
      { tags: [...tags], ...(cursor === undefined ? {} : { cursor }) },
      undefined,
      context,
    );
    transactions.push(...page.transactions);
    cursor = nextScanCursor(cursor, page);
    if (cursor === undefined) return transactions;
  }
}
