import { rightAlign, checkedBytes, u32be } from "@heliuslabs/zolana/internal";
import { type Bytes32, poseidon } from "@heliuslabs/zolana/keypair";

/** Distinct ASCII tags, the first Poseidon input, mirroring Rust `custom_ring_interface::domain`. */
export const RingDomain = Object.freeze({
  deliveredSlotSecret: 0x4352_4453, // "CRDS"
  recipientTagDomain: 0x4352_5254, // "CRRT"
  senderTagDomain: 0x4352_5354, // "CRST"
  blindingSeed: 0x4352_4253, // "CRBS"
  transferStatement: 0x4352_5458, // "CRTX"
  policyTable: 0x4352_5442, // "CRTB"
  queueWrite: 0x4352_5157, // "CRQW"
  applyRecords: 0x4352_4150, // "CRAP"
  registerKey: 0x4352_5247, // "CRRG"
  depositBlinding: 0x4352_4442, // "CRDB"
  depositStatement: 0x4352_4450, // "CRDP"
  mergeStatement: 0x4352_4d47, // "CRMG"
  withdrawals: 0x4352_5057, // "CRPW"
  recordUpdate: 0x4352_5255, // "CRRU"
  walletGrant: 0x4352_5747, // "CRWG"
  addressRecord: 0x4352_4144, // "CRAD"
} as const);
export type RingDomain = (typeof RingDomain)[keyof typeof RingDomain];

/** The nonzero last element of every transfer statement, a layout change raises it. */
export const TRANSFER_STATEMENT_VERSION = 3n;

export function domainField(domain: RingDomain): Bytes32 {
  return rightAlign(u32be(domain));
}

/** `Poseidon(domain, ...fields)` over fresh copies, wiped once hashed since they may hold secrets. */
export function domainHash(domain: RingDomain, fields: readonly Uint8Array[]): Bytes32 {
  try {
    return poseidon([domainField(domain), ...fields]) as Bytes32;
  } finally {
    fields.forEach((field) => field.fill(0));
  }
}

/** `Poseidon(CRDB, blinding_secret)`. */
export function depositBlinding(blindingSecret: Bytes32): Bytes32 {
  return domainHash(RingDomain.depositBlinding, [
    checkedBytes<Bytes32>(blindingSecret, 32, "deposit blinding secret"),
  ]);
}
