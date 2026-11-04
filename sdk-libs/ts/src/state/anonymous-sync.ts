/** Transfers found by scanning each ring's history and deposits by tag, Rust `zolana_ring_client::anonymous`. */
import { getBase58Encoder, type ReadonlyUint8Array } from "@solana/kit";

import { ClientError, type IndexerReader, type IndexerRpcConfig } from "@heliuslabs/zolana/client";
import {
  bytesKey,
  equalBytes,
  isCanonicalField,
  isZero,
  PAGE_LIMIT,
  ZERO_NULLIFIER_PK,
} from "@heliuslabs/zolana/internal";
import type { Address, Bytes16, Bytes32, RequestContext } from "@heliuslabs/zolana/interface";
import {
  X25519PublicKey,
  type ShieldedAddress,
  type ShieldedPublicKey,
  type ViewingKey,
  type ViewTag,
} from "@heliuslabs/zolana/keypair";
import {
  SOL_MINT,
  transactOutputBlinding,
  type AssetRegistry,
  type DepositPayloadDecoder,
  type IndexedShieldedTransaction,
  type OutputSlot,
  type ShieldedKeys,
  type Utxo,
  type WalletUtxo,
} from "@heliuslabs/zolana/transaction";

import { slotTag, txKeySlotSecret } from "../crypto/derivation/ring-stream.js";
import { isSmallOrder, x25519FromU } from "../crypto/keys/x25519.js";
import {
  openRecipientBody,
  openReply,
  openSenderBundle,
  senderBundleLen,
  type RecipientBody,
  type ReplyMetadata,
  type SenderBundle,
} from "../protocol/codec/anonymous-delivery.js";
import { customRingDepositPayload } from "../protocol/transaction/deposit-payload.js";
import { ringBodyOutput, senderBundleOutputBody } from "../protocol/transaction/output.js";
import { openRecipientNote } from "../crypto/derivation/blinding.js";
import { HalvingPageLimit, readRingPages, scanLimits, type ScanLimits } from "../rpc/history.js";
import { answered, unseen } from "./batch.js";
import { isZeroKeyNote as isExposedNote, zeroKeyNullifier } from "./exposed-notes.js";
import { openZeroKeyMerges, type OpenedZeroKeyMerge } from "./zero-key-merge.js";
import { decoded, openRingDeposit, type RingDepositNote } from "./ring-deposit.js";
import { registeredMint } from "../operations/workflow/recover.js";
import { isRingMergeRow, openRingMerges } from "./ring-sync.js";
import type { RingKeys, RingTagFrame } from "./ring-keys.js";
import { RingError } from "../protocol/error.js";
import {
  GapScan,
  type EntryStream,
  ViewingHistory,
  type ViewingKeyEntry,
  viewTagStream,
} from "./viewing-history.js";

/** The indexer's cap on the tags or nullifiers one request names. */
export const TAGS_PER_REQUEST = Number(PAGE_LIMIT);

/** How a sync found a note. */
export type AnonymousStream =
  /** A deposit to the wallet's own note under `senderViewTag(index)`. */
  | Readonly<{ kind: "sender"; index: bigint }>
  /** A deposit under a tag the wallet minted for a request. */
  | Readonly<{ kind: "request"; index: bigint }>
  | Readonly<{ kind: "bootstrap" }>
  /** A transfer's slot or bundle whose proven tag matched. */
  | Readonly<{ kind: "provenTag" }>
  | Readonly<{ kind: "merge"; firstNullifier: Bytes32 }>
  /** Tried with no use of its tag. */
  | Readonly<{ kind: "fullScan" }>;

export interface AnonymousRingUtxo {
  readonly utxoHash: Bytes32;
  readonly viewingPublicKey: X25519PublicKey;
  /** The registered key or `ZERO_NULLIFIER_PK`, whichever rebuilt. */
  readonly nullifierPublicKey: Bytes32;
  readonly stream: AnonymousStream;
}

export type SentCheck =
  /** A held recipient address rebuilt the published hash under `mint`. */
  | Readonly<{ kind: "verified"; mint: Address }>
  /** No held address names the viewing key and rebuilds the hash. */
  | Readonly<{ kind: "unverified" }>;

/** One payment the wallet's sender bundle lists, its body opened with the transaction key. */
export interface SentPayment {
  readonly txSignature: IndexedShieldedTransaction["txSignature"];
  readonly utxoHash: Bytes32;
  readonly position: number;
  readonly recipientViewingPublicKey: X25519PublicKey;
  /** The held address that rebuilt the hash, `undefined` under an unverified check. */
  readonly ownerPublicKey: ShieldedPublicKey | undefined;
  readonly amount: bigint;
  readonly check: SentCheck;
}

/** An unauthenticated sender claim, `confirmReplyClaim` alone learns from it. */
export interface ReplyClaim {
  readonly utxoHash: Bytes32;
  readonly reply: ReplyMetadata;
}

export interface AnonymousRecovery {
  /** The notes found, spent once a fetched transaction spends them. */
  readonly utxos: readonly WalletUtxo[];
  readonly spentNullifiers: readonly Bytes32[];
  readonly found: readonly AnonymousRingUtxo[];
  /** The replies on found notes, a frame without one adds none. */
  readonly replyClaims: readonly ReplyClaim[];
  /** The wallet's payments in the transfers it sent, a body that fails to open left out. */
  readonly sent: readonly SentPayment[];
  /** Notes under a mint the registry lacks, stored and unspendable until it registers, no rescan needed. */
  readonly pendingOpenings: readonly WalletUtxo[];
  /** Rebuilt mints missing from the asset registry. */
  readonly unknownMints: readonly Address[];
  /** The output hash of each note in `pendingOpenings`. */
  readonly unmatched: readonly Bytes32[];
}

/** Bodies no held key rebuilt, an owner's note under a bad body opens only through an auditor read. */
export interface AuditorRecovery {
  /** Commitments, foreign notes and dummies among them. */
  readonly unopened: readonly Bytes32[];
}

export interface AnonymousScan extends AnonymousRecovery {
  /** Filled by a full scan alone. */
  readonly auditorRecovery: AuditorRecovery;
  /** Counters, watermarks and ring positions as read, `AnonymousWallet.absorb` stores them with the notes. */
  readonly history: ViewingHistory;
}

/** A scan a sync issued and no absorb took, no copy carries a position past its notes. */
const issuedScans = new WeakMap<AnonymousScan, ViewingHistory>();

/** @internal `AnonymousWallet.absorb` alone. */
export function consumeScan(scan: AnonymousScan, history: ViewingHistory): void {
  const original = issuedScans.get(scan);
  if (original === undefined) throw new RingError("RING_SCAN_CONSUMED");
  if (!history._progressMatches(original)) throw new RingError("RING_SCAN_HISTORY_CHANGED");
  issuedScans.delete(scan);
}

export type AnonymousSyncClient = Pick<
  IndexerReader,
  | "getShieldedTransactionsByTags"
  | "getEncryptedUtxosByTags"
  | "getShieldedTransactionsByNullifiers"
>;

type SyncKeys = ShieldedKeys & RingKeys;

/** What opens a body, every secret stays with `keys`. */
interface BodyReads {
  readonly keys: SyncKeys;
  readonly assets: AssetRegistry;
  readonly recipients: readonly ShieldedAddress[];
}

interface SyncFields extends BodyReads {
  readonly config: IndexerRpcConfig | undefined;
  readonly depositPayload: DepositPayloadDecoder;
  readonly fullRescan: boolean;
  readonly held: readonly WalletUtxo[];
  readonly limits: ScanLimits;
  readonly senderFastPath: boolean;
  readonly tagMatcher: Pick<RingKeys, "ringTagMatches">;
}

/** Scans each ring of the history and reads each held key's deposit streams. */
export class AnonymousSync {
  readonly #fields: SyncFields;

  private constructor(fields: SyncFields) {
    this.#fields = fields;
    Object.freeze(this);
  }

  static create(keys: ShieldedKeys & RingKeys, assets: AssetRegistry): AnonymousSync {
    return new AnonymousSync({
      keys,
      assets,
      config: undefined,
      depositPayload: customRingDepositPayload,
      fullRescan: false,
      held: [],
      recipients: [],
      limits: SCAN_TO_TERMINAL,
      senderFastPath: false,
      tagMatcher: keys,
    });
  }

  withIndexerConfig(config: IndexerRpcConfig): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, config });
  }

  /** A framing of the deposit ciphertexts other than the audit capsule. */
  withDepositPayload(depositPayload: DepositPayloadDecoder): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, depositPayload });
  }

  /** Every stream from index 0 and every ring from its start, for a wallet that keeps no notes between syncs. */
  withFullRescan(): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, fullRescan: true });
  }

  /** Include pending openings to retain their later spends. */
  withHeldNotes(held: readonly WalletUtxo[]): AnonymousSync {
    return new AnonymousSync({
      ...this.#fields,
      held: Object.freeze([...held]),
    });
  }

  /** The recipients' addresses the wallet holds, a sent payment verifies only against one. */
  withRecipientAddresses(recipients: readonly ShieldedAddress[]): AnonymousSync {
    return new AnonymousSync({
      ...this.#fields,
      recipients: Object.freeze([...recipients]),
    });
  }

  /** A capped read stores no position, the next sync reads the same pages. */
  withScanLimits(input: Readonly<{ pageSize?: number; maxPages?: number }>): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, limits: scanLimits(input) });
  }

  /** Moves the tag test off the main thread, the matcher's worker is the key's holder. */
  withTagMatcher(tagMatcher: Pick<RingKeys, "ringTagMatches">): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, tagMatcher });
  }

  /** A bundle under the wallet's own transaction key skips its tag test, every other candidate keeps it. */
  withSenderFastPath(): AnonymousSync {
    return new AnonymousSync({ ...this.#fields, senderFastPath: true });
  }

  /** An entry whose key the holder lacks stays as stored, a held key without an entry is refused until the history adds it. */
  async fetch(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    const scan = this.#scan(client, history, context);
    await scan.entries();
    await scan.rings();
    await scan.merges();
    await scan.zeroKeyMerges();
    return scan.result();
  }

  /** Tries every slot, bundle and deposit of `ring` from its start with no use of a tag, spends resolve from the same pages. */
  async fullScan(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    ring: Address,
    context?: RequestContext,
  ): Promise<AnonymousScan> {
    const scan = this.#scan(client, history, context);
    await scan.recover(ring);
    await scan.zeroKeyMerges();
    return scan.result();
  }

  #scan(
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context: RequestContext | undefined,
  ): Scan {
    if (this.#fields.keys.viewingPublicKeys().some((key) => history.entry(key) === undefined))
      throw new RingError("RING_VIEWING_HISTORY_INVALID", {
        details: { reason: "a held viewing key has no entry" },
      });
    return new Scan(this.#fields, client, history, context);
  }
}

export interface RingFullScan {
  /** Under the wallet's own nullifier key. */
  readonly utxos: readonly WalletUtxo[];
  /** Unspent zero-key notes in publication order. */
  readonly exposedIfSpent: readonly WalletUtxo[];
  /** The nullifiers of the spent zero-key notes. */
  readonly spentExposed: readonly Bytes32[];
  readonly pending: readonly WalletUtxo[];
  readonly auditorRecovery: AuditorRecovery;
}

/** A wrong tag hides nothing here, every held key tries every site of `ring`. */
export async function ringFullScan(
  input: Readonly<{
    keys: SyncKeys;
    assets: AssetRegistry;
    client: AnonymousSyncClient;
    ring: Address;
    config?: IndexerRpcConfig;
  }>,
  context?: RequestContext,
): Promise<RingFullScan> {
  const [current, ...retired] = [...input.keys.viewingPublicKeys()].reverse();
  if (current === undefined)
    throw new RingError("RING_VIEWING_HISTORY_INVALID", {
      details: { reason: "no held viewing key" },
    });
  const history = retired
    .reduce(
      (held, key, index) => held.withRotatedKey(key, BigInt(index + 1)),
      ViewingHistory.create(current, 0n),
    )
    .withRing(input.ring);
  const sync = AnonymousSync.create(input.keys, input.assets);
  const scan = await (
    input.config === undefined ? sync : sync.withIndexerConfig(input.config)
  ).fullScan(input.client, history, input.ring, context);
  const zeroKey = scan.utxos.filter(isExposedNote);
  return Object.freeze({
    utxos: Object.freeze(scan.utxos.filter((note) => !isExposedNote(note))),
    exposedIfSpent: Object.freeze(zeroKey.filter((note) => !note.spent)),
    spentExposed: Object.freeze(zeroKey.filter((note) => note.spent).map((note) => note.nullifier)),
    pending: scan.pendingOpenings,
    auditorRecovery: scan.auditorRecovery,
  });
}

/** One round's tags, every read of a published tag goes through `match`. */
class TagWindow<T> {
  readonly #byTag = new Map<string, T>();
  readonly tags: readonly ViewTag[];

  constructor(tags: readonly (readonly [T, ViewTag])[]) {
    for (const [index, tag] of tags) this.#byTag.set(bytesKey(tag), index);
    this.tags = tags.map(([, tag]) => tag);
  }

  match(published: Readonly<{ viewTag: Bytes32 }>): T | undefined {
    return this.#byTag.get(bytesKey(published.viewTag));
  }
}

type ActiveStream = Readonly<{ stream: EntryStream; scan: GapScan }>;

type RoundTag = Readonly<{ kind: "bootstrap" }> | Readonly<{ stream: EntryStream; index: bigint }>;

async function streamTags(
  keys: RingKeys,
  viewingPublicKey: X25519PublicKey,
  stream: EntryStream,
  counters: readonly bigint[],
  context: RequestContext | undefined,
): Promise<readonly ViewTag[]> {
  const requests = counters.map((at) => ({
    viewingPublicKey,
    stream: viewTagStream(stream, at),
  }));
  return answered(requests, await keys.viewTags(requests, context)).map(([, tag]) => tag);
}

/** Rust `RingDeliveryContext`. */
interface SlotContext {
  readonly ring: Address;
  readonly txViewingPublicKey: X25519PublicKey;
  readonly salt: Bytes16;
  readonly firstNullifier: Bytes32;
}

/** A recipient body at an output, a sender bundle in a message. */
type Site =
  | Readonly<{ kind: "output"; position: number }>
  | Readonly<{ kind: "message"; message: number }>;

/** A scheme 13 body or a scheme 12 bundle a held key may open. */
interface Body {
  readonly tx: IndexedShieldedTransaction;
  readonly site: Site;
  readonly ciphertext: Uint8Array;
  readonly reply: Uint8Array;
  readonly context: SlotContext;
  readonly found: AnonymousStream;
}

/** A note whose rebuilt hash matched, before its nullifier. */
interface Found extends RingDepositNote {
  readonly outputContext: WalletUtxo["outputContext"];
  readonly nullifierPublicKey: Bytes32;
  readonly order: Publication;
  /** Under a mint the registry lacks. */
  readonly pending?: boolean;
}

/** Where a note was published, the order a scan returns its notes in. */
interface Publication {
  readonly slot: bigint;
  readonly signature: ReadonlyUint8Array;
  readonly position: number;
}

type Deposit = Readonly<{
  slot: bigint;
  txSignature: IndexedShieldedTransaction["txSignature"];
  outputSlot: OutputSlot;
}>;

interface Decrypted {
  readonly utxo: WalletUtxo;
  readonly order: Publication;
}

type Rebuilt = Readonly<{
  utxo: Utxo;
  nullifierPublicKey: Bytes32;
  dataHash?: Bytes32;
  ringDataHash?: Bytes32;
}>;

/** A body the reader's own keys rebuilt. */
interface RebuiltNote extends Rebuilt {
  readonly body: Body;
  readonly position: number;
  readonly reply: ReplyMetadata | undefined;
  readonly pending: boolean;
}

class Scan {
  readonly #unopened = new Map<string, Bytes32>();
  readonly #sync: SyncFields;
  readonly #client: AnonymousSyncClient;
  readonly #context: RequestContext | undefined;
  readonly #address: ShieldedAddress;
  readonly #ledger: NoteLedger;
  readonly #originalHistory: ViewingHistory;
  readonly #pageLimit = new HalvingPageLimit(TAGS_PER_REQUEST);
  readonly #ringRows: IndexedShieldedTransaction[] = [];
  #history: ViewingHistory;

  constructor(
    sync: SyncFields,
    client: AnonymousSyncClient,
    history: ViewingHistory,
    context: RequestContext | undefined,
  ) {
    this.#sync = sync;
    this.#client = client;
    this.#context = context;
    this.#address = sync.keys.address();
    this.#ledger = new NoteLedger(sync.keys, sync.held);
    this.#originalHistory = history;
    this.#history = history;
  }

  async entries(): Promise<void> {
    for (const [index, entry] of this.#history.entries.entries())
      if (this.#holds(entry)) await this.entry(index);
  }

  /** One key's deposit streams, every round's tags in one read. */
  async entry(index: number): Promise<void> {
    const entry = this.#entry(index);
    const { viewingPublicKey } = entry;
    const streams: readonly EntryStream[] = ["tx", "request"];
    let active = streams.map(
      (stream): ActiveStream => ({
        stream,
        scan: new GapScan(this.#sync.fullRescan ? 0n : entry[stream].scanned, entry[stream]),
      }),
    );
    let bootstrap: readonly ViewTag[] = [viewingPublicKey.u(), slotTag(viewingPublicKey.u())];
    while (active.length > 0) {
      const tagged: (readonly [RoundTag, ViewTag])[] = bootstrap.map((tag) => [BOOTSTRAP, tag]);
      bootstrap = [];
      for (const { stream, scan } of active) {
        const indices = scan.round();
        const tags = await streamTags(
          this.#sync.keys,
          viewingPublicKey,
          stream,
          indices,
          this.#context,
        );
        for (const [at, tag] of answered(indices, tags)) tagged.push([{ stream, index: at }, tag]);
      }
      const seen = await this.#window(index, new TagWindow(tagged));
      active = active.filter(({ stream, scan }) => {
        const found = [...seen].flatMap((tag) =>
          "stream" in tag && tag.stream === stream ? [tag.index] : [],
        );
        if (scan.advance(found)) return true;
        const current = this.#entry(index);
        this.#withEntry(index, current.withCounter(stream, scan.finish(current[stream])));
        return false;
      });
    }
  }

  /** Entries at one position of one ring share a read, a key added later is its own query. */
  async rings(): Promise<void> {
    const reads = new Map<
      string,
      Readonly<{ ring: Address; afterSlot: bigint | null; keys: X25519PublicKey[] }>
    >();
    for (const entry of this.#history.entries.filter((held) => this.#holds(held)))
      for (const { ring, afterSlot } of entry.ringPositions()) {
        const position = this.#sync.fullRescan ? null : afterSlot;
        const key = `${ring}:${String(position)}`;
        const read = reads.get(key) ?? { ring, afterSlot: position, keys: [] };
        read.keys.push(entry.viewingPublicKey);
        reads.set(key, read);
      }
    for (const { ring, afterSlot, keys } of reads.values())
      await this.#readRing({ ring, afterSlot, keys, trial: "provenTags" });
  }

  /** Recovery, every site tried under every held key from the ring's start. */
  async recover(ring: Address): Promise<void> {
    const keys = this.#history.entries
      .filter((held) => this.#holds(held))
      .map((entry) => entry.viewingPublicKey);
    const merges = new LocalMerges();
    await this.#readRing({ ring, afterSlot: null, keys, trial: "everySite", merges });
    // Every merge was read, a note outside the frontier opens it as well.
    let unread: readonly IndexedShieldedTransaction[] = merges.rows();
    await openMerges({ ...this.#mergeReads(), historyUnread: true }, () => {
      const rows = unread;
      unread = [];
      return Promise.resolve(rows);
    });
  }

  /** The spends of every found or held ring note, round after round, open the ring merges among them. */
  merges(): Promise<void> {
    return openMerges(this.#mergeReads(), (frontier) =>
      this.#paged(frontier, (nullifiers, token, limit) =>
        this.#client
          .getShieldedTransactionsByNullifiers(
            { nullifiers, ...token, limit },
            this.#sync.config,
            this.#context,
          )
          .then((page) => ({ ...page, items: page.data.flatMap((item) => item.events) })),
      ),
    );
  }

  /** Tagged by the owner's identity, read from every ring row a scan passed. */
  async zeroKeyMerges(): Promise<void> {
    const opened = await openZeroKeyMerges(
      { keys: this.#sync.keys, owner: this.#address, rows: this.#ringRows },
      this.#context,
    );
    this.#ledger.keepZeroKeyMerges(opened, this.#sync.assets);
  }

  async result(): Promise<AnonymousScan> {
    const recovery = await this.#ledger.recovery(this.#context);
    for (const note of [...recovery.utxos, ...recovery.pendingOpenings])
      this.#unopened.delete(bytesKey(note.outputContext.hash));
    const scan: AnonymousScan = Object.freeze({
      ...recovery,
      auditorRecovery: Object.freeze({
        unopened: Object.freeze(
          [...this.#unopened.entries()]
            .sort(([left], [right]) => (left < right ? -1 : 1))
            .map(([, hash]) => hash),
        ),
      }),
      history: this.#history,
    });
    issuedScans.set(scan, this.#originalHistory);
    return scan;
  }

  #holds(entry: ViewingKeyEntry): boolean {
    return this.#sync.keys.viewingPublicKeys().some((key) => key.equals(entry.viewingPublicKey));
  }

  #mergeReads() {
    return {
      keys: this.#sync.keys,
      owner: this.#address,
      assets: this.#sync.assets,
      ledger: this.#ledger,
      held: this.#sync.held,
      context: this.#context,
    };
  }

  /** Reads to a terminal page, only its `context.slot` becomes a position. */
  async #readRing(
    read: Readonly<{
      ring: Address;
      afterSlot: bigint | null;
      keys: readonly X25519PublicKey[];
      trial: "provenTags" | "everySite";
      merges?: LocalMerges;
    }>,
  ): Promise<void> {
    const { ring, afterSlot, keys, trial } = read;
    const seen = new Set<string>();
    const reach = await readRingPages(
      {
        client: this.#client,
        ringProgramId: ring,
        limits: this.#sync.limits,
        ...(afterSlot === null ? {} : { afterSlot }),
        ...(this.#sync.config === undefined ? {} : { config: this.#sync.config }),
      },
      async (rows) => {
        const fresh = rows.filter((tx) => unseen(seen, txKey(tx)));
        this.#ledger.noteSpends(fresh);
        this.#ringRows.push(...fresh);
        read.merges?.add(fresh);
        for (const viewingPublicKey of keys)
          if (trial === "provenTags") await this.#testTags(viewingPublicKey, fresh);
          else await this.#tryEverySite(viewingPublicKey, fresh);
      },
      this.#context,
    );
    if (reach.checkpoint === undefined) return;
    const { checkpoint } = reach;
    this.#history = keys.reduce(
      (history, key) => history._withRingCheckpoint(ring, key, checkpoint),
      this.#history,
    );
  }

  /** One agreement per candidate per key inside the holder, only a matching tag opens a body. */
  async #testTags(
    viewingPublicKey: X25519PublicKey,
    rows: readonly IndexedShieldedTransaction[],
  ): Promise<void> {
    const candidates = rows
      .map((tx) => sitesOf(tx).flatMap((site) => bodyAt(tx, site, PROVEN_TAG) ?? []))
      .filter((bodies) => bodies.length > 0);
    if (candidates.length === 0) return;
    const recognized = await this.#ownBundles(viewingPublicKey, candidates.flat());
    const tested = candidates
      .map((bodies) => bodies.filter((body) => !recognized.has(body)))
      .filter((bodies) => bodies.length > 0);
    const frames = tested.flatMap((bodies): RingTagFrame[] => {
      const [first] = bodies;
      if (first === undefined) return [];
      const { txViewingPublicKey, salt, firstNullifier } = first.context;
      return [
        {
          viewingPublicKey,
          txViewingPublicKey,
          salt,
          firstNullifier,
          probes: bodies.map(bodyProbe),
        },
      ];
    });
    const answers =
      frames.length === 0 ? [] : await this.#sync.tagMatcher.ringTagMatches(frames, this.#context);
    const matched = answered(tested, answers).flatMap(([bodies, frameAnswers]) =>
      answered(bodies, frameAnswers).flatMap(([body, secret]) =>
        secret === undefined ? [] : [[body, secret] as const],
      ),
    );
    await this.#read(viewingPublicKey, [
      ...matched,
      ...(await bodySecrets(this.#sync.keys, viewingPublicKey, [...recognized], this.#context)),
    ]);
  }

  /** The fast path's bundles, a proof under another transaction key keeps its tag test. */
  async #ownBundles(
    viewingPublicKey: X25519PublicKey,
    bodies: readonly Body[],
  ): Promise<ReadonlySet<Body>> {
    if (!this.#sync.senderFastPath) return new Set();
    const own = await ownTransactions(this.#sync.keys, viewingPublicKey, bodies, this.#context);
    for (const key of own.values()) key.destroy();
    return new Set(
      bodies.filter(
        (body) => body.site.kind === "message" && own.has(bytesKey(body.context.firstNullifier)),
      ),
    );
  }

  /** The one recovery path of every rail, no tag is read here. */
  async #tryEverySite(
    viewingPublicKey: X25519PublicKey,
    rows: readonly IndexedShieldedTransaction[],
  ): Promise<void> {
    for (const slot of rows.flatMap((tx) => tx.outputSlots))
      if (ringBodyOutput(slot.payload) !== undefined)
        this.#unopened.set(bytesKey(slot.outputContext.hash), slot.outputContext.hash);
    const bodies = rows.flatMap((tx) =>
      sitesOf(tx).flatMap((site) => bodyAt(tx, site, FULL_SCAN) ?? []),
    );
    await this.#read(
      viewingPublicKey,
      await bodySecrets(this.#sync.keys, viewingPublicKey, bodies, this.#context),
    );
    for (const deposit of rows.filter((tx) => tx.proofless).flatMap(depositsOf))
      await openDepositNote(
        {
          keys: this.#sync.keys,
          assets: this.#sync.assets,
          owner: this.#address,
          ledger: this.#ledger,
          depositPayload: this.#sync.depositPayload,
          viewingPublicKey,
          deposit,
          found: FULL_SCAN,
        },
        this.#context,
      );
  }

  async #read(
    viewingPublicKey: X25519PublicKey,
    opened: readonly (readonly [Body, Bytes32])[],
  ): Promise<void> {
    this.#ledger.absorb(
      viewingPublicKey,
      await readBodies(this.#sync, viewingPublicKey, opened, this.#context),
    );
  }

  /** Opens every deposit under a tag of `window`, the tags any deposit holds. */
  async #window(index: number, window: TagWindow<RoundTag>): Promise<ReadonlySet<RoundTag>> {
    const deposits = await this.#deposits(window.tags);
    const observed = new Set<RoundTag>();
    for (const deposit of deposits) {
      const at = window.match(deposit.outputSlot);
      if (at === undefined) continue;
      observed.add(at);
      await openDepositNote(
        {
          keys: this.#sync.keys,
          assets: this.#sync.assets,
          owner: this.#address,
          ledger: this.#ledger,
          depositPayload: this.#sync.depositPayload,
          viewingPublicKey: this.#entry(index).viewingPublicKey,
          deposit,
          found: "stream" in at ? foundIn(at.stream, at.index) : BOOTSTRAP,
        },
        this.#context,
      );
    }
    return observed;
  }

  /** The deposits published under one of `tags`, one per deposited output. */
  #deposits(tags: readonly ViewTag[]): Promise<readonly Deposit[]> {
    return this.#paged(tags, (chunk, token, limit) =>
      this.#client
        .getEncryptedUtxosByTags({ tags: chunk, ...token, limit }, this.#sync.config, this.#context)
        .then((page) => ({
          ...page,
          items: page.data.flatMap((item) => item.outputs),
        })),
    );
  }

  /** Every page of every chunk, a null token ends a chunk's read. */
  async #paged<T>(
    queried: readonly Bytes32[],
    fetch: (
      chunk: Bytes32[],
      token: Readonly<{ paginationToken?: string }>,
      limit: number,
    ) => Promise<Readonly<{ items: readonly T[]; paginationToken: string | null }>>,
  ): Promise<readonly T[]> {
    const items: T[] = [];
    for (let start = 0; start < queried.length; start += TAGS_PER_REQUEST) {
      const chunk = queried.slice(start, start + TAGS_PER_REQUEST);
      const followed = new Set<string>();
      let token: string | undefined;
      for (;;) {
        const asked = token === undefined ? {} : { paginationToken: token };
        const page = await this.#pageLimit.read((limit) => fetch(chunk, asked, limit));
        items.push(...page.items);
        token = page.paginationToken ?? undefined;
        if (token === undefined) break;
        if (followed.has(token))
          throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
            details: { path: "$.paginationToken" },
          });
        followed.add(token);
      }
    }
    return items;
  }

  #entry(index: number): ViewingKeyEntry {
    const entry = this.#history.entries[index];
    if (entry === undefined)
      throw new RingError("RING_VIEWING_HISTORY_INVALID", {
        details: { reason: "names no viewing key at the index" },
      });
    return entry;
  }

  #withEntry(index: number, entry: ViewingKeyEntry): void {
    this.#history = this.#history.withEntry(index, entry);
  }
}

/** The merge rows of a recovery's pages, a merge spends its owner's notes. */
class LocalMerges {
  readonly #byNullifier = new Map<string, IndexedShieldedTransaction[]>();

  add(rows: readonly IndexedShieldedTransaction[]): void {
    for (const tx of rows.filter(isRingMergeRow))
      for (const nullifier of tx.nullifiers) {
        const key = bytesKey(nullifier);
        this.#byNullifier.set(key, [...(this.#byNullifier.get(key) ?? []), tx]);
      }
  }

  rows(): readonly IndexedShieldedTransaction[] {
    return [...new Set([...this.#byNullifier.values()].flat())];
  }
}

/** The merges spending the found and held ring notes, round after round. */
async function openMerges(
  input: Readonly<{
    keys: ShieldedKeys;
    owner: ShieldedAddress;
    assets: AssetRegistry;
    ledger: NoteLedger;
    held: readonly WalletUtxo[];
    context: RequestContext | undefined;
    historyUnread?: boolean;
  }>,
  spendsOf: (frontier: readonly Bytes32[]) => Promise<readonly IndexedShieldedTransaction[]>,
): Promise<void> {
  const { ledger, held, owner, context } = input;
  let historyUnread = input.historyUnread === true;
  const queried = new Set<string>();
  const heldRing = held
    .filter((utxo) => utxo.utxo.ringProgramId !== undefined)
    .map((utxo) => utxo.nullifier);
  const isHeld = (hash: Bytes32): boolean =>
    ledger.isFound(hash) || held.some((entry) => equalBytes(entry.outputContext.hash, hash));
  for (;;) {
    await ledger.assignNullifiers(context);
    const frontier = [...ledger.ringNullifiers(), ...heldRing].filter((nullifier) =>
      unseen(queried, bytesKey(nullifier)),
    );
    if (frontier.length === 0 && !historyUnread) return;
    historyUnread = false;
    const spends = await spendsOf(frontier);
    ledger.noteSpends(spends);
    const { merges, utxos } = await openRingMerges(
      { keys: input.keys, owner, assets: input.assets, spends },
      context,
    );
    for (const merge of merges) {
      const firstNullifier = merge.nullifiers[0];
      if (firstNullifier === undefined) continue;
      for (const [position, slot] of merge.outputSlots.entries()) {
        const hash = slot.outputContext.hash;
        const utxo = utxos.find((entry) => equalBytes(entry.outputContext.hash, hash));
        if (utxo === undefined || isHeld(hash)) continue;
        const pending = registeredMint(input.assets, utxo.utxo.asset) === undefined;
        if (pending) ledger.unknownMint(utxo.utxo.asset);
        ledger.keep(
          {
            utxo: utxo.utxo,
            pending,
            outputContext: utxo.outputContext,
            nullifierPublicKey: owner.nullifierPublicKey,
            order: publication(merge, position),
          },
          owner.viewingPublicKey,
          Object.freeze({ kind: "merge", firstNullifier }),
        );
      }
    }
  }
}

/** One deposit under one key, its published hash proves it the owner's. */
async function openDepositNote(
  input: Readonly<{
    keys: ShieldedKeys;
    assets: AssetRegistry;
    owner: ShieldedAddress;
    ledger: NoteLedger;
    depositPayload: DepositPayloadDecoder;
    viewingPublicKey: X25519PublicKey;
    deposit: Deposit;
    found: AnonymousStream;
  }>,
  context: RequestContext | undefined,
): Promise<void> {
  const { deposit, ledger, owner, viewingPublicKey } = input;
  const slot = deposit.outputSlot;
  if (ledger.isFound(slot.outputContext.hash)) return;
  const opened = await openRingDeposit(
    {
      keys: input.keys,
      owner,
      viewingPublicKey,
      outputSlot: slot,
      depositPayload: input.depositPayload,
    },
    context,
  );
  if (opened === undefined) return;
  const pending = registeredMint(input.assets, opened.utxo.asset) === undefined;
  if (pending) ledger.unknownMint(opened.utxo.asset);
  ledger.keep(
    {
      ...opened,
      pending,
      outputContext: walletContext(slot),
      order: {
        slot: deposit.slot,
        signature: base58.encode(deposit.txSignature),
        position: 0,
      },
    },
    viewingPublicKey,
    input.found,
  );
}

/** The notes one sync or recovery keeps, each once, under the stream that found it. */
class NoteLedger {
  readonly #keys: ShieldedKeys;
  /** Only a spend of these or of a found note leaves the ledger, a ring's other spends are not the wallet's. */
  readonly #held: readonly WalletUtxo[];
  #found: Found[] = [];
  readonly #decrypted: Decrypted[] = [];
  readonly #pending: Decrypted[] = [];
  readonly #streams: AnonymousRingUtxo[] = [];
  readonly #spends = new Set<string>();
  readonly #spent = new Map<string, Bytes32>();
  readonly #replyClaims: ReplyClaim[] = [];
  readonly #sent: SentPayment[] = [];
  readonly #unknownMints = new Set<Address>();

  constructor(keys: ShieldedKeys, held: readonly WalletUtxo[]) {
    this.#keys = keys;
    this.#held = held;
  }

  /** A claim stays with its note, a note found twice adds none. */
  absorb(viewingPublicKey: X25519PublicKey, read: BodyRead): void {
    for (const { utxo, nullifierPublicKey, body, position, reply, pending } of read.notes) {
      const slot = body.tx.outputSlots[position];
      if (slot === undefined || this.isFound(slot.outputContext.hash)) continue;
      this.keep(
        {
          utxo,
          nullifierPublicKey,
          pending,
          outputContext: walletContext(slot),
          order: publication(body.tx, position),
        },
        viewingPublicKey,
        body.found,
      );
      if (reply !== undefined)
        this.#replyClaims.push(Object.freeze({ utxoHash: slot.outputContext.hash, reply }));
    }
    this.#sent.push(...read.sent);
    for (const mint of read.unknownMints) this.unknownMint(mint);
  }

  keep(note: Found, viewingPublicKey: X25519PublicKey, stream: AnonymousStream): void {
    this.#found.push(note);
    this.#streams.push(
      Object.freeze({
        utxoHash: note.outputContext.hash,
        viewingPublicKey,
        nullifierPublicKey: note.nullifierPublicKey,
        stream,
      }),
    );
  }

  unknownMint(mint: Address): void {
    this.#unknownMints.add(mint);
  }

  keepZeroKeyMerges(opened: readonly OpenedZeroKeyMerge[], assets: AssetRegistry): void {
    for (const { utxo, row, position, viewingPublicKey } of opened) {
      const hash = utxo.outputContext.hash;
      if (this.isFound(hash)) continue;
      const firstNullifier = row.nullifiers[0];
      if (firstNullifier === undefined) continue;
      const pending = registeredMint(assets, utxo.utxo.asset) === undefined;
      if (pending) this.unknownMint(utxo.utxo.asset);
      (pending ? this.#pending : this.#decrypted).push({
        utxo,
        order: publication(row, position),
      });
      this.#streams.push(
        Object.freeze({
          utxoHash: hash,
          viewingPublicKey,
          nullifierPublicKey: ZERO_NULLIFIER_PK as Bytes32,
          stream: Object.freeze({ kind: "merge" as const, firstNullifier }),
        }),
      );
    }
  }

  isFound(hash: Bytes32): boolean {
    const same = (context: WalletUtxo["outputContext"]) => equalBytes(context.hash, hash);
    return (
      this.#found.some(({ outputContext }) => same(outputContext)) ||
      [...this.#decrypted, ...this.#pending].some(({ utxo }) => same(utxo.outputContext))
    );
  }

  noteSpends(transactions: readonly IndexedShieldedTransaction[]): void {
    for (const tx of transactions) {
      if (!unseen(this.#spends, txKey(tx))) continue;
      for (const nullifier of tx.nullifiers) this.#spent.set(bytesKey(nullifier), nullifier);
    }
  }

  /** Derives the nullifiers of the found notes in publication order. */
  async assignNullifiers(context: RequestContext | undefined): Promise<void> {
    const found = this.#found;
    this.#found = [];
    const registered = found.filter((note) => !isZeroKeyNote(note));
    const derived =
      registered.length === 0
        ? []
        : await this.#keys.derive(
            registered.map(({ utxo, outputContext }) => ({
              kind: "nullifier" as const,
              utxoHash: outputContext.hash,
              blinding: utxo.blinding,
            })),
            context,
          );
    const nullifiers = new Map(answered(registered, derived));
    for (const note of found) {
      const { order, nullifierPublicKey: _nullifierPublicKey, ...fields } = note;
      const nullifier =
        nullifiers.get(note) ?? zeroKeyNullifier(fields.outputContext.hash, fields.utxo.blinding);
      const { pending, ...kept } = fields;
      (pending === true ? this.#pending : this.#decrypted).push({
        utxo: Object.freeze({ ...kept, nullifier, spent: false }),
        order,
      });
    }
    this.#decrypted.sort((left, right) => compareOrder(left.order, right.order));
    this.#pending.sort((left, right) => compareOrder(left.order, right.order));
  }

  ringNullifiers(): readonly Bytes32[] {
    return [...this.#decrypted, ...this.#pending]
      .filter(({ utxo }) => utxo.utxo.ringProgramId !== undefined)
      .map(({ utxo }) => utxo.nullifier);
  }

  async recovery(context: RequestContext | undefined): Promise<AnonymousRecovery> {
    await this.assignNullifiers(context);
    return Object.freeze({
      utxos: this.#marked(this.#decrypted),
      pendingOpenings: this.#marked(this.#pending),
      spentNullifiers: Object.freeze(
        [...this.#decrypted, ...this.#pending, ...this.#held.map((utxo) => ({ utxo }))].flatMap(
          ({ utxo: { nullifier } }) => (this.#spent.has(bytesKey(nullifier)) ? [nullifier] : []),
        ),
      ),
      found: Object.freeze([...this.#streams]),
      replyClaims: Object.freeze([...this.#replyClaims]),
      sent: Object.freeze([...this.#sent]),
      unknownMints: Object.freeze([...this.#unknownMints]),
      unmatched: Object.freeze(this.#pending.map(({ utxo }) => utxo.outputContext.hash)),
    });
  }

  #marked(notes: readonly Decrypted[]): readonly WalletUtxo[] {
    return Object.freeze(
      notes.map(({ utxo }) =>
        Object.freeze({ ...utxo, spent: this.#spent.has(bytesKey(utxo.nullifier)) }),
      ),
    );
  }
}

/** One viewing key's reading of a batch of bodies. */
class BodyRead {
  readonly notes: RebuiltNote[] = [];
  readonly unknownMints: Address[] = [];
  readonly sent: SentPayment[] = [];
  readonly #reads: BodyReads;
  readonly #owner: ShieldedAddress;

  constructor(reads: BodyReads) {
    this.#reads = reads;
    this.#owner = reads.keys.address();
  }

  recipientBody(body: Body, position: number, secret: Bytes32): void {
    const opening = decoded(() => openRecipientBody(secret, body.ciphertext));
    if (opening === undefined) return;
    this.#note(body, position, opening, replyOf(body.reply, secret));
  }

  /** Each change slot the bundle rebuilds, then the payments only the sender's own key proves. */
  senderBundle(body: Body, secret: Bytes32, txViewingKey: ViewingKey | undefined): void {
    const bundle = decoded(() =>
      openSenderBundle(secret, body.ciphertext, body.tx.outputSlots.length),
    );
    if (bundle === undefined) return;
    try {
      for (const position of changePositions(body.tx)) {
        const opening = decoded(() => changeOpening(bundle, body.context.firstNullifier, position));
        this.#note(body, position, opening, undefined);
      }
    } finally {
      bundle.outputSeed.fill(0);
    }
    if (txViewingKey === undefined) return;
    for (const [position, recipient] of listedRecipients(bundle)) {
      const sent = this.#sentPayment(body, position, recipient, txViewingKey);
      if (sent !== undefined) this.sent.push(sent);
    }
  }

  /** Only a rebuilt commitment counts, the cipher authenticates nothing. */
  #note(
    body: Body,
    position: number,
    opening: RecipientBody | undefined,
    reply: ReplyMetadata | undefined,
  ): void {
    const slot = body.tx.outputSlots[position];
    if (slot === undefined || opening === undefined) return;
    const rebuilt = rebuild(this.#reads.assets, this.#owner, slot, body.context.ring, opening);
    if (rebuilt !== undefined) this.#keep(body, position, rebuilt, reply);
  }

  /** A mint the registry lacks holds the note back, the scan still moves past it. */
  #keep(body: Body, position: number, rebuilt: Rebuilt, reply: ReplyMetadata | undefined): void {
    const slot = body.tx.outputSlots[position];
    if (slot === undefined) return;
    const mint = rebuilt.utxo.asset;
    const pending = registeredMint(this.#reads.assets, mint) === undefined;
    if (pending) this.unknownMints.push(mint);
    this.notes.push({ ...rebuilt, body, position, reply, pending });
  }

  /** `undefined` when the body at `position` fails to open under the recipient's key. */
  #sentPayment(
    body: Body,
    position: number,
    recipient: X25519PublicKey,
    txViewingKey: ViewingKey,
  ): SentPayment | undefined {
    const slot = body.tx.outputSlots[position];
    const parts = slot === undefined ? undefined : ringBodyOutput(slot.payload);
    if (slot === undefined || parts === undefined) return undefined;
    const opening = decoded(() => {
      const secret = txKeySlotSecret({
        txViewingKey,
        recipientViewingKey: recipient,
        salt: body.context.salt,
        outputIndex: position,
        firstNullifier: body.context.firstNullifier,
      });
      try {
        return openRecipientBody(secret, parts.body);
      } finally {
        secret.fill(0);
      }
    });
    if (opening === undefined) return undefined;
    const verified = this.#reads.recipients.find(
      (address) =>
        address.viewingPublicKey.equals(recipient) &&
        rebuild(this.#reads.assets, address, slot, body.context.ring, opening) !== undefined,
    );
    return Object.freeze({
      txSignature: body.tx.txSignature,
      utxoHash: slot.outputContext.hash,
      position,
      recipientViewingPublicKey: recipient,
      ownerPublicKey: verified?.signingPublicKey,
      amount: opening.amount,
      check: Object.freeze(
        verified === undefined
          ? { kind: "unverified" as const }
          : { kind: "verified" as const, mint: opening.mint },
      ),
    });
  }
}

/** Each body's slot secret, one agreement per transaction inside the holder. */
async function bodySecrets(
  keys: RingKeys,
  viewingPublicKey: X25519PublicKey,
  bodies: readonly Body[],
  context: RequestContext | undefined,
): Promise<readonly (readonly [Body, Bytes32])[]> {
  if (bodies.length === 0) return [];
  return answered(
    bodies,
    await keys.ringDeliverySecrets(
      bodies.map((body) => ({
        viewingPublicKey,
        txViewingPublicKey: body.context.txViewingPublicKey,
        salt: body.context.salt,
        outputIndex: outputIndex(body),
        firstNullifier: body.context.firstNullifier,
      })),
      context,
    ),
  );
}

/** Wipes every secret it reads. */
async function readBodies(
  reads: BodyReads,
  viewingPublicKey: X25519PublicKey,
  opened: readonly (readonly [Body, Bytes32])[],
  context: RequestContext | undefined,
): Promise<BodyRead> {
  const read = new BodyRead(reads);
  let own: ReadonlyMap<string, ViewingKey> = new Map();
  try {
    own = await ownTransactions(
      reads.keys,
      viewingPublicKey,
      opened.map(([body]) => body),
      context,
    );
    for (const [body, secret] of opened) {
      if (body.site.kind === "output") read.recipientBody(body, body.site.position, secret);
      else read.senderBundle(body, secret, own.get(bytesKey(body.context.firstNullifier)));
    }
  } finally {
    for (const [, secret] of opened) secret.fill(0);
    for (const txViewingKey of own.values()) txViewingKey.destroy();
  }
  return read;
}

/** The transaction key of each transaction the entry's key sent, keyed by its first nullifier. */
async function ownTransactions(
  keys: ShieldedKeys,
  viewingPublicKey: X25519PublicKey,
  bodies: readonly Body[],
  context: RequestContext | undefined,
): Promise<ReadonlyMap<string, ViewingKey>> {
  const contexts = new Map<string, SlotContext>();
  for (const body of bodies)
    if (body.site.kind === "message")
      contexts.set(bytesKey(body.context.firstNullifier), body.context);
  if (contexts.size === 0) return new Map();
  const held = [...contexts.values()];
  const derived = answered(
    held,
    await keys.transactionKeys(
      held.map((slot) => ({
        viewingPublicKey,
        firstNullifier: slot.firstNullifier,
      })),
      context,
    ),
  );
  const own = new Map<string, ViewingKey>();
  derived.forEach(([slot, txViewingKey]) => {
    // Another viewing key sent the transaction.
    if (!txViewingKey.publicKey().equals(slot.txViewingPublicKey)) {
      txViewingKey.destroy();
      return;
    }
    own.set(bytesKey(slot.firstNullifier), txViewingKey);
  });
  return own;
}

/** Tries the registered key then the zero key, a third key misses. */
function rebuild(
  assets: AssetRegistry,
  owner: ShieldedAddress,
  slot: OutputSlot,
  ring: Address,
  opening: RecipientBody,
): Rebuilt | undefined {
  const { hash, treeId } = slot.outputContext;
  if (treeId === undefined) return undefined;
  return decoded(() =>
    openRecipientNote({ owner, ring, treeId, commitment: hash, assets }, opening),
  );
}

/** Slot 0 holds the bundle's mint, slot 1 only SOL. */
function changeOpening(
  bundle: SenderBundle,
  firstNullifier: Bytes32,
  position: number,
): RecipientBody {
  const cell =
    position === 0
      ? { mint: bundle.mint, amount: bundle.amount }
      : { mint: SOL_MINT, amount: bundle.solAmount };
  return Object.freeze({
    ...cell,
    blinding: transactOutputBlinding(firstNullifier, bundle.outputSeed, position),
  });
}

/** A slot with no payload is change, any other pattern than a prefix of at most two reads as none. */
function changePositions(tx: IndexedShieldedTransaction): readonly number[] {
  const bare = tx.outputSlots.map((slot) => slot.payload.length === 0);
  const firstPaid = bare.indexOf(false);
  const count = firstPaid < 0 ? bare.length : firstPaid;
  if (count > MAX_CHANGE_SLOTS || bare.slice(count).includes(true)) return [];
  return Array.from({ length: count }, (_, position) => position);
}

/** Zero cells and keys no ECDH accepts left out, each key beside its slot. */
function listedRecipients(bundle: SenderBundle): readonly (readonly [number, X25519PublicKey])[] {
  return bundle.recipientKeys.flatMap((key, position) => {
    if (isZero(key)) return [];
    const recipient = decoded(() => x25519FromU(key));
    return recipient === undefined || isSmallOrder(recipient)
      ? []
      : [[position, recipient] as const];
  });
}

function sitesOf(tx: IndexedShieldedTransaction): readonly Site[] {
  return [
    ...tx.outputSlots.map((_, position): Site => ({ kind: "output", position })),
    ...tx.messages.map((_, message): Site => ({ kind: "message", message })),
  ];
}

/** `undefined` for a site that holds no well formed body or bundle. */
function bodyAt(
  tx: IndexedShieldedTransaction,
  site: Site,
  found: AnonymousStream,
): Body | undefined {
  const context = slotContext(tx);
  if (context === undefined) return undefined;
  if (site.kind === "output") {
    const slot = tx.outputSlots[site.position];
    const parts = slot === undefined ? undefined : ringBodyOutput(slot.payload);
    return parts === undefined
      ? undefined
      : { tx, site, ciphertext: parts.body, reply: parts.reply, context, found };
  }
  const message = tx.messages[site.message];
  const bundle = message === undefined ? undefined : senderBundleOutputBody(message.data);
  // Compact slots never reach the event, a bundle of any other `m` opens under another secret.
  return bundle?.length === senderBundleLen(tx.outputSlots.length)
    ? { tx, site, ciphertext: bundle, reply: new Uint8Array(), context, found }
    : undefined;
}

/** `undefined` without a reply or on bytes that never decode. */
function replyOf(reply: Uint8Array, secret: Bytes32): ReplyMetadata | undefined {
  return reply.length === 0 ? undefined : decoded(() => openReply(secret, reply));
}

/** A body at its position, a bundle at `m`, past every body's index. */
function outputIndex(body: Body): number {
  return body.site.kind === "output" ? body.site.position : body.tx.outputSlots.length;
}

const BOOTSTRAP = Object.freeze({ kind: "bootstrap" });
const FULL_SCAN: AnonymousStream = Object.freeze({ kind: "fullScan" });
const PROVEN_TAG: AnonymousStream = Object.freeze({ kind: "provenTag" });
/** A capped read never moves a position, a scan runs to its terminal page. */
const SCAN_TO_TERMINAL = scanLimits({ maxPages: Number.MAX_SAFE_INTEGER });
const MAX_CHANGE_SLOTS = 2;
const base58 = getBase58Encoder();

function isZeroKeyNote(note: Found): boolean {
  return equalBytes(note.nullifierPublicKey, ZERO_NULLIFIER_PK);
}

function foundIn(stream: EntryStream, index: bigint): AnonymousStream {
  return Object.freeze({ kind: stream === "tx" ? "sender" : "request", index });
}

function txKey(tx: IndexedShieldedTransaction): string {
  return `${tx.txSignature}:${String(tx.eventIndex)}`;
}

/** `undefined` without a ring, a contributory key, a salt or a canonical first nullifier. */
function slotContext(tx: IndexedShieldedTransaction): SlotContext | undefined {
  const { ringProgramId: ring, txViewingPublicKey, salt } = tx;
  const firstNullifier = tx.nullifiers[0];
  if (
    ring === undefined ||
    txViewingPublicKey === undefined ||
    salt === undefined ||
    firstNullifier === undefined ||
    isSmallOrder(txViewingPublicKey) ||
    !isCanonicalField(firstNullifier)
  )
    return undefined;
  return { ring, txViewingPublicKey, salt, firstNullifier };
}

function walletContext(slot: OutputSlot): WalletUtxo["outputContext"] {
  return Object.freeze({
    hash: slot.outputContext.hash,
    tree: slot.outputContext.tree,
    leafIndex: slot.outputContext.leafIndex,
  });
}

/** A slot answers under the recipient domain, a bundle under the sender's at index `m`. */
function bodyProbe(body: Body): RingTagFrame["probes"][number] {
  const { site, tx } = body;
  const published =
    site.kind === "output" ? tx.outputSlots[site.position] : tx.messages[site.message];
  if (published === undefined)
    throw new RingError("RING_VIEWING_HISTORY_INVALID", { details: { reason: "no such site" } });
  return {
    kind: site.kind === "output" ? "recipient" : "senderBundle",
    outputIndex: outputIndex(body),
    tag: published.viewTag,
  };
}

function depositsOf(tx: IndexedShieldedTransaction): readonly Deposit[] {
  return tx.outputSlots.map((outputSlot) => ({
    slot: tx.slot,
    txSignature: tx.txSignature,
    outputSlot,
  }));
}

function publication(tx: IndexedShieldedTransaction, position: number): Publication {
  return { slot: tx.slot, signature: base58.encode(tx.txSignature), position };
}

/** Slot, then signature bytes, then output position. */
function compareOrder(left: Publication, right: Publication): number {
  if (left.slot !== right.slot) return left.slot < right.slot ? -1 : 1;
  const length = Math.min(left.signature.length, right.signature.length);
  for (let at = 0; at < length; at++) {
    const difference = (left.signature[at] ?? 0) - (right.signature[at] ?? 0);
    if (difference !== 0) return difference;
  }
  return left.signature.length - right.signature.length || left.position - right.position;
}
