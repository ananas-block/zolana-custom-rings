/**
 * A ring's audit credentials as Photon and the SPP tree accounts serve them, the one stub every
 * `resolveCredentials` read in the tests goes through.
 *
 * Tree 0 holds both namespaces, as `DEFAULT_TREE_ID` and `ADDRESS_TREE_ID` coincide. Its state
 * history keeps one root over every enrolled credential leaf, and its address history one root over
 * the lone low leaf `(0, FIELD_MAX)`, so every owner never enrolled proves absent under that root.
 */
import type { Address } from "@solana/kit";

import type { CredentialClient } from "../../src/rpc/credential-resolver.js";
import type { RpcAccount } from "@heliuslabs/zolana/client";
import { poseidon, treeAddress, ZERO_32 } from "@heliuslabs/zolana/internal";
import {
  NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET,
  NULLIFIER_ROOT_HISTORY_OFFSET,
  NULLIFIER_TREE_HEIGHT,
  SHIELDED_POOL_PROGRAM_ID,
  STATE_HEIGHT,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  UTXO_ROOT_HISTORY_CAPACITY,
  UTXO_ROOT_HISTORY_CAPACITY_OFFSET,
  UTXO_ROOT_HISTORY_CURSOR_OFFSET,
  UTXO_ROOT_HISTORY_LEN_OFFSET,
  UTXO_ROOT_HISTORY_OFFSET,
  UTXO_SUBTREES_LEN_OFFSET,
  type Bytes32,
  type Bytes33,
  type Bytes64,
} from "@heliuslabs/zolana/interface";
import type { ShieldedAddress } from "@heliuslabs/zolana/keypair";
import type { IndexedShieldedTransaction } from "@heliuslabs/zolana/transaction";

import { ringIdField } from "../../src/crypto/derivation/ring-stream.js";
import {
  ADDRESS_TREE_ID,
  NULLIFIER_SEQUENCE_OFFSET,
  credentialAddress,
  credentialPda,
  credentialSeed,
  credentialUtxoHash,
  encodeAuditCredential,
  encodeCredentialOutput,
  type AuditCredential,
} from "../../src/protocol/membership/credential.js";
import { FIELD_MAX } from "../../src/protocol/membership/member-opening.js";
import { CredentialRoots } from "../../src/protocol/codec/credential-read.js";
import { stateTreeAt } from "./state-tree.js";

const TREE = treeAddress(ADDRESS_TREE_ID);
const CONTEXT = Object.freeze({ slot: 1n, blockTime: 0n });
/** The siblings of leaf 0 in an otherwise empty indexed tree, and the root over `(0, FIELD_MAX)`. */
function addressTree(): Readonly<{ path: readonly Bytes32[]; root: Bytes32 }> {
  const path: Bytes32[] = [ZERO_32];
  while (path.length < NULLIFIER_TREE_HEIGHT) {
    const below = path.at(-1) as Bytes32;
    path.push(poseidon([below, below]) as Bytes32);
  }
  const root = path.reduce<Bytes32>(
    (node, sibling) => poseidon([node, sibling]) as Bytes32,
    poseidon([ZERO_32, FIELD_MAX]) as Bytes32,
  );
  return Object.freeze({ path: Object.freeze(path), root });
}

interface Enrolled {
  readonly credential: AuditCredential;
  readonly address: Bytes32;
  readonly leaf: Bytes32;
  readonly leafIndex: number;
  readonly event: IndexedShieldedTransaction;
}

export class CredentialChain {
  readonly #ring: Address;
  readonly #pda: Address;
  readonly #auditorPubkey: Bytes33;
  readonly #accounts: Map<Address, RpcAccount>;
  readonly #enrolled = new Map<string, Enrolled>();
  readonly #address = addressTree();

  private constructor(
    input: Readonly<{
      ringProgramId: Address;
      pda: Address;
      auditorPubkey: Bytes33;
      accounts: Map<Address, RpcAccount>;
    }>,
  ) {
    this.#ring = input.ringProgramId;
    this.#pda = input.pda;
    this.#auditorPubkey = input.auditorPubkey;
    this.#accounts = input.accounts;
    this.#publish();
  }

  /** Writes tree 0 into `accounts`, the map the fixture's chain reads. */
  static async create(
    input: Readonly<{
      ringProgramId: Address;
      auditorPubkey: Bytes33;
      accounts: Map<Address, RpcAccount>;
    }>,
  ): Promise<CredentialChain> {
    return new CredentialChain({ ...input, pda: await credentialPda(input.ringProgramId) });
  }

  /** A chain on its own accounts with `owners` enrolled, for a client built by hand. */
  static async enrolled(
    ringProgramId: Address,
    owners: readonly ShieldedAddress[],
  ): Promise<CredentialChain> {
    const chain = await CredentialChain.create({
      ringProgramId,
      auditorPubkey: new Uint8Array(33) as Bytes33,
      accounts: new Map(),
    });
    for (const owner of owners) chain.enroll(owner);
    return chain;
  }

  /** Tree 0 and any account the chain was given. */
  account(address: Address): RpcAccount | undefined {
    return this.#accounts.get(address);
  }

  /** `Enroll` landed and its leaf is under the newest state root. */
  enroll(owner: ShieldedAddress, listTag: Bytes32 = ZERO_32): AuditCredential {
    const credential: AuditCredential = Object.freeze({
      ringId: ringIdField(this.#ring),
      member: owner.signingPublicKey.ownerProofInputHash(),
      nullifierPk: owner.nullifierPublicKey,
      listTag,
      auditorPubkey: this.#auditorPubkey,
      ephU: new Uint8Array(32).fill(0x13) as Bytes32,
      ciphertext: new Uint8Array(64).fill(0x21) as Bytes64,
    });
    const key = Buffer.from(credential.member).toString("hex");
    const held = this.#enrolled.get(key);
    // A second `Enroll` of the same credential changes nothing, another credential is refused.
    if (held !== undefined) {
      if (!same(encodeAuditCredential(held.credential), encodeAuditCredential(credential)))
        throw new Error("a credential is never replaced");
      return held.credential;
    }
    const pda = this.#pda;
    const address = credentialAddress(pda, credentialSeed(credential.ringId, credential.member));
    const leaf = credentialUtxoHash({ pda, address, credential, treeId: ADDRESS_TREE_ID });
    const leafIndex = this.#enrolled.size;
    this.#enrolled.set(key, {
      credential,
      address,
      leaf,
      leafIndex,
      event: {
        slot: 1n,
        txSignature: `enroll${leafIndex}` as IndexedShieldedTransaction["txSignature"],
        outputSlots: [
          {
            viewTag: ZERO_32,
            outputContext: {
              hash: leaf,
              tree: TREE,
              treeId: ADDRESS_TREE_ID,
              leafIndex: BigInt(leafIndex),
            },
            payload: encodeCredentialOutput(address, credential),
          },
        ],
        messages: [],
        nullifiers: [address],
        proofless: false,
      },
    });
    this.#publish();
    return credential;
  }

  /** The Photon reads and the account snapshot `resolveCredentials` takes. */
  reader(): CredentialClient {
    const enrolled = () => [...this.#enrolled.values()];
    return {
      getAccount: async (key) => this.#accounts.get(key),
      getMultipleAccounts: async (keys) => keys.map((key) => this.#accounts.get(key)),
      getShieldedTransactionsByNullifiers: async (request) => ({
        context: CONTEXT,
        data: enrolled()
          .filter(({ address }) => request.nullifiers.some((nullifier) => same(nullifier, address)))
          .map(({ event }) => ({
            slot: event.slot,
            signature: event.txSignature,
            events: [event],
          })),
        paginationToken: null,
      }),
      getMerkleProofs: async (_tree, leaves) => {
        const state = this.#state();
        return {
          context: CONTEXT,
          proofs: enrolled()
            .filter(({ leaf }) => leaves.some((requested) => same(requested, leaf)))
            .map(({ leaf, leafIndex }) => ({
              leaf,
              merkleContext: { treeType: 0, tree: TREE },
              path: state.path(leafIndex),
              leafIndex: BigInt(leafIndex),
              root: state.root,
              rootSeq: 1n,
              rootIndex: 0,
            })),
        };
      },
      getNonInclusionProofs: async (_tree, addresses) => ({
        context: CONTEXT,
        proofs: addresses.map((leaf) => ({
          leaf,
          merkleContext: { treeType: 0, tree: TREE },
          path: this.#address.path,
          lowElement: ZERO_32,
          lowElementIndex: 0n,
          highElement: FIELD_MAX,
          highElementIndex: 1n,
          root: this.#address.root,
          rootSeq: 0n,
          rootIndex: 0,
        })),
      }),
    } as CredentialClient;
  }

  #state() {
    return stateTreeAt(
      new Map([...this.#enrolled.values()].map((entry) => [entry.leafIndex, entry.leaf])),
    );
  }

  /** One state root in slot 0, one address root in slot 0 at sequence 0. */
  #publish(): void {
    const data = new Uint8Array(TREE_ACCOUNT_SIZE);
    const view = new DataView(data.buffer);
    data[0] = StateDiscriminator.treeAccount;
    data[1] = 1;
    view.setUint16(2, ADDRESS_TREE_ID, true);
    view.setUint16(UTXO_ROOT_HISTORY_CURSOR_OFFSET, 0, true);
    view.setUint16(UTXO_ROOT_HISTORY_LEN_OFFSET, 1, true);
    view.setUint16(UTXO_ROOT_HISTORY_CAPACITY_OFFSET, UTXO_ROOT_HISTORY_CAPACITY, true);
    data[UTXO_SUBTREES_LEN_OFFSET] = STATE_HEIGHT;
    data.set(this.#state().root, UTXO_ROOT_HISTORY_OFFSET);
    view.setBigUint64(NULLIFIER_SEQUENCE_OFFSET, 0n, true);
    view.setBigUint64(NULLIFIER_ROOT_HISTORY_CURSOR_OFFSET, 1n, true);
    data.set(this.#address.root, NULLIFIER_ROOT_HISTORY_OFFSET);
    this.#accounts.set(TREE, { owner: SHIELDED_POOL_PROGRAM_ID, data, lamports: 1n });
  }
}

function same(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, at) => byte === right[at]);
}

/**
 * A vector's flat `credential_fields`, `[owner, address_root, tree_id_0, root_0, ...]`, hex with
 * or without `0x`. `stateOnly` reads a merge table, `[owner, tree_id, root]`.
 */
export function vectorCredentialRoots(
  fields: readonly string[],
  stateOnly = false,
): CredentialRoots {
  const elements = fields.map(
    (value) => Uint8Array.from(Buffer.from(value.replace(/^0x/, ""), "hex")) as Bytes32,
  );
  const [ownerHash, ...rest] = elements;
  const addressRoot = stateOnly ? ZERO_32 : rest.shift();
  if (ownerHash === undefined || addressRoot === undefined || rest.length % 2 !== 0)
    throw new Error("credential fields");
  return CredentialRoots.read({
    ownerHash,
    addressRoot: addressRoot as Bytes32,
    stateRoots: Array.from({ length: rest.length / 2 }, (_, pair) => ({
      treeId: Number(BigInt(`0x${Buffer.from(rest[2 * pair] as Bytes32).toString("hex")}`)),
      root: rest[2 * pair + 1] as Bytes32,
    })),
  });
}
