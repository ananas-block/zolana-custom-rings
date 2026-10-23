import {
  getAddressEncoder,
  getProgramDerivedAddress,
  type Address,
  type ProgramDerivedAddress,
  type ReadonlyUint8Array,
} from "@solana/kit";

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();

function ringPda(
  ringProgramId: Address,
  ...seeds: readonly ReadonlyUint8Array[]
): Promise<ProgramDerivedAddress> {
  return getProgramDerivedAddress({ programAddress: ringProgramId, seeds: [...seeds] });
}

async function ringAddress(pda: Promise<ProgramDerivedAddress>): Promise<Address> {
  return (await pda)[0];
}

/** Mirrors Rust `CustomRing::cosigner_pda`, uninitialized when the ring has no co-signer. */
export function ringCoSignerPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("cosigner"));
}

export function ringCoSignerAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringCoSignerPda(ringProgramId));
}

export function ringConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("config"));
}

export function ringConfigAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringConfigPda(ringProgramId));
}

export function ringDepositAuditPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("deposit_audit"));
}

export function ringDepositAuditAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringDepositAuditPda(ringProgramId));
}

/** Mirrors Rust `CustomRing::policy_config_pda`. */
export function ringPolicyConfigPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("policy"));
}

export function ringPolicyConfigAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringPolicyConfigPda(ringProgramId));
}

/** Mirrors Rust `CustomRing::delegate_pda`, uninitialized when the ring has no delegate. */
export function ringDelegatePda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("delegate"));
}

export function ringDelegateAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringDelegatePda(ringProgramId));
}

/** Mirrors Rust `CustomRing::spend_window_pda`, SOL under the zero address. */
export function ringSpendWindowPda(
  ringProgramId: Address,
  mint: Address,
): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("window"), addressEncoder.encode(mint));
}

export function ringSpendWindowAddress(ringProgramId: Address, mint: Address): Promise<Address> {
  return ringAddress(ringSpendWindowPda(ringProgramId, mint));
}

export function ringKeyRegistryRootPda(ringProgramId: Address): Promise<ProgramDerivedAddress> {
  return ringPda(ringProgramId, encoder.encode("keyreg"));
}

export function ringKeyRegistryRootAddress(ringProgramId: Address): Promise<Address> {
  return ringAddress(ringKeyRegistryRootPda(ringProgramId));
}
