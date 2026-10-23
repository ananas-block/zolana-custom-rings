import type { Instruction } from "@solana/kit";
import type { Address } from "@heliuslabs/zolana";
import { type RingAssetDeposit, InstructionTag } from "@heliuslabs/zolana/interface";
import {
  Writer,
  copyBytes,
  fail,
  encodeRingDepositInstructionData,
  ringAuthAddress,
  depositLayout,
  depositAssetIndex,
  depositAccounts,
  instruction,
  tagged,
  meta,
  SYSTEM_PROGRAM,
} from "@heliuslabs/zolana/internal";
import {
  ringConfigAddress,
  ringCoSignerAddress,
  ringDepositAuditAddress,
  ringKeyRegistryRootAddress,
} from "../interface/pda/index.js";
import { ringCoSignerMetas, ringSpendWindowMetas } from "../interface/instructions/index.js";
import type { SignerAccount } from "@heliuslabs/zolana/instructions";
import { CUSTOM_RING_PROOF_LENGTH } from "../interface/custom-ring-proof.js";
import {
  AUDITED_RING_DEPOSIT_TAG,
  RING_DEPOSIT_AUDIT_SLOTS,
  readRingDepositCapsule,
} from "./deposit-capsule.js";
import { RingError } from "./error.js";

export async function ringDepositInstruction(
  input: Readonly<{
    ringProgramId: Address;
    tree: Address;
    depositor: SignerAccount;
    deposits: readonly RingAssetDeposit[];
    proof?: Uint8Array;
    cosigner?: SignerAccount;
    /** The registry history slot of the bound root, present exactly when the ring escrows keys. */
    keyRegistryRootIndex?: number;
  }>,
): Promise<Instruction> {
  const layout = depositLayout(input.deposits);
  if (input.keyRegistryRootIndex !== undefined && input.proof === undefined) {
    throw new RingError("RING_DEPOSIT_AUDIT_REQUIRED", { details: { reason: "keyEscrow" } });
  }
  if (input.proof !== undefined) {
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
  }
  const [ringAuth, config, cosignerPda, depositAudit, keyRegistryRoot, windows] = await Promise.all(
    [
      ringAuthAddress(input.ringProgramId),
      ringConfigAddress(input.ringProgramId),
      ringCoSignerAddress(input.ringProgramId),
      ringDepositAuditAddress(input.ringProgramId),
      input.keyRegistryRootIndex === undefined
        ? undefined
        : ringKeyRegistryRootAddress(input.ringProgramId),
      ringSpendWindowMetas(input.ringProgramId, [
        ...(layout.hasSol ? [SYSTEM_PROGRAM] : []),
        ...layout.splGroups.map((spl) => spl.mint),
      ]),
    ],
  );
  const { accounts, splInterfaceBumps } = await depositAccounts(
    input.tree,
    input.depositor,
    layout,
    ringAuth,
  );
  accounts.unshift(
    meta(config, false, false),
    ...ringCoSignerMetas(cosignerPda, input.cosigner),
    meta(depositAudit, false, false),
    ...(keyRegistryRoot === undefined ? [] : [meta(keyRegistryRoot, false, false)]),
    ...windows,
  );
  const sppWire = tagged(
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
  return instruction(
    input.proof === undefined
      ? sppWire
      : tagged(
          AUDITED_RING_DEPOSIT_TAG,
          new Uint8Array([
            ...copyBytes(input.proof, CUSTOM_RING_PROOF_LENGTH, "deposit proof"),
            ...new Writer().u8(input.keyRegistryRootIndex ?? 0, "keyRegistryRootIndex").finish(),
            ...sppWire,
          ]),
        ),
    accounts,
    input.ringProgramId,
  );
}
