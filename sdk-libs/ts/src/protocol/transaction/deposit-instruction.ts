import type { AccountMeta, Instruction } from "@solana/kit";

import { CUSTOM_RING_PROOF_LENGTH } from "../proof/custom-ring-proof.js";
import {
  encodeRingDepositInstructionData,
  depositAccounts,
  depositAssetIndex,
  depositLayout,
  instruction,
  meta,
  tagged,
  type SignerAccount,
  Writer,
  fail,
} from "@heliuslabs/zolana/internal";
import { InstructionTag } from "@heliuslabs/zolana/interface";
import type { Address, RingAssetDeposit } from "@heliuslabs/zolana/interface";
import { ringAuthAddress, ringCoSignerMetas, ringPolicyAddress } from "../pda/index.js";
import type { CredentialRead } from "../codec/credential-read.js";

import { RING_DEPOSIT_AUDIT_SLOTS, readRingDepositCapsule } from "../codec/deposit-capsule.js";
import { RingInstructionTag } from "./instruction-tag.js";

/** The SPP ring deposit the ring program forwards unchanged, Rust `RingDeposit`. */
export interface RingDepositSpp {
  /** `RING_DEPOSIT ‖ RingDepositIxData`, the bytes the deposit proof binds. */
  readonly data: Uint8Array;
  readonly accounts: readonly AccountMeta[];
}

/** Tag, key capacity and proof, then the credential read's address index and state count. */
const DEPOSIT_PREFIX_HEAD = 2 + CUSTOM_RING_PROOF_LENGTH;
/** The own and curator revisions past the credential read. */
const DEPOSIT_PREFIX_TAIL = 16;

/** The SPP deposit a ring deposit forwards, Rust `DepositPrefix::parse` rest, `undefined` off the layout. */
export function depositSppData(data: Uint8Array): Uint8Array | undefined {
  const stateReads = data[DEPOSIT_PREFIX_HEAD + 2];
  if (data[0] !== RingInstructionTag.deposit || stateReads === undefined) return undefined;
  const length = DEPOSIT_PREFIX_HEAD + 3 + 2 * stateReads + DEPOSIT_PREFIX_TAIL;
  return data.length < length ? undefined : data.subarray(length);
}

/** The accounts `[ring, registries, address tree, state trees, co_signer?]` ahead of SPP's deposit list. */
export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
    /** The deposit key's slots, every key proves one statement. */
    keyCapacity: number;
    proof: Uint8Array;
    /** Read only, the policy registries right after the ring account. */
    registries: readonly Address[];
    /** Its state reads fit the deposit key's `K`. */
    credentialRead: CredentialRead;
    /** Tree 0, then each state tree the read names, in table order. */
    credentialTrees: readonly Address[];
    /** Policy rings only. */
    ownRevision?: bigint;
    /** Rings with a curator source only. */
    curatorRevision?: bigint;
    /** The supplied co-signer when a record covers deposits. */
    cosigner?: SignerAccount;
  }>,
): Promise<Instruction> {
  const [spp, ring, cosigner] = await Promise.all([
    ringDepositSpp(input),
    ringPolicyAddress(input.ringProgramId),
    input.cosigner === undefined ? [] : ringCoSignerMetas(input.ringProgramId, input.cosigner),
  ]);
  const prefix = new Writer()
    .u8(input.keyCapacity, "keyCapacity")
    .bytes(input.proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof");
  input.credentialRead.checkCapacity(input.keyCapacity);
  input.credentialRead
    .write(prefix)
    .u64(input.ownRevision ?? 0n, "ownRevision")
    .u64(input.curatorRevision ?? 0n, "curatorRevision")
    .finish();
  return instruction(
    tagged(RingInstructionTag.deposit, new Uint8Array([...prefix, ...spp.data])),
    [
      meta(ring, false, false),
      ...input.registries.map((registry) => meta(registry, false, false)),
      ...input.credentialTrees.map((tree) => meta(tree, false, false)),
      ...cosigner,
      ...spp.accounts,
    ],
    input.ringProgramId,
  );
}

/** One capsule per output at its own slot, all under one ephemeral key, as the program reads them. */
export async function ringDepositSpp(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
  }>,
): Promise<RingDepositSpp> {
  if (input.deposits.length > RING_DEPOSIT_AUDIT_SLOTS)
    fail("INTERFACE_CODEC", { field: "deposit count" });
  let ephemeralKey: Uint8Array | undefined;
  for (const [index, deposit] of input.deposits.entries()) {
    const capsule = readRingDepositCapsule(deposit.encrypted.ciphertext);
    if (
      capsule === undefined ||
      capsule.slotIndex !== index ||
      (ephemeralKey !== undefined &&
        !ephemeralKey.every((byte, offset) => capsule.ephemeralPublicKey[offset] === byte))
    )
      fail("INTERFACE_CODEC", { field: "deposit capsule" });
    ephemeralKey = capsule.ephemeralPublicKey;
  }
  const layout = depositLayout(input.deposits);
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    await ringAuthAddress(input.ringProgramId),
  );
  const data = tagged(
    InstructionTag.ringDeposit,
    encodeRingDepositInstructionData({
      assets: [
        ...(layout.hasSol ? ([{ kind: "sol" }] as const) : []),
        ...splInterfaceBumps.map((splInterfaceBump) => ({
          kind: "spl" as const,
          splInterfaceBump,
        })),
      ],
      deposits: input.deposits.map((deposit) => ({
        assetIndex: depositAssetIndex(layout, deposit),
        viewTag: deposit.viewTag,
        ownerUtxoHash: deposit.ownerUtxoHash,
        amount: deposit.amount,
        ringDataHash: deposit.ringDataHash,
        encrypted: deposit.encrypted,
      })),
    }),
  );
  return Object.freeze({ data, accounts: Object.freeze(accounts) });
}
