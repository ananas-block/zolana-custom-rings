/** Tag 31 capsules, read and never written by a new deposit. Rust keeps no reader for them. */
import { copyBytes, fail } from "@heliuslabs/zolana/internal";
import type { Bytes33, Bytes96 } from "@heliuslabs/zolana";

export const HISTORICAL_DEPOSIT_AUDIT_SLOTS = 8;
/** One opening is `ownerHash || blinding || ownerKey`. */
export const HISTORICAL_DEPOSIT_OPENING_LENGTH = 96;
export const HISTORICAL_DEPOSIT_OWNER_KEY_OFFSET = 64;
/** `tag || proof || own_revision || curator_revision` ahead of the forwarded SPP deposit. */
export const HISTORICAL_DEPOSIT_PREFIX_LENGTH = 1 + 192 + 2 * 8;
const MAGIC = new TextEncoder().encode("CRDEP001");
const HEADER_LENGTH = 42 + HISTORICAL_DEPOSIT_OPENING_LENGTH;

export interface HistoricalDepositCapsule {
  readonly slotIndex: number;
  readonly ephemeralPublicKey: Bytes33;
  readonly ciphertext: Bytes96;
  readonly recipientCiphertext: Uint8Array;
}

export function encodeHistoricalDepositCapsule(input: HistoricalDepositCapsule): Uint8Array {
  if (
    !Number.isInteger(input.slotIndex) ||
    input.slotIndex < 0 ||
    input.slotIndex >= HISTORICAL_DEPOSIT_AUDIT_SLOTS
  )
    fail("INTERFACE_CODEC", { field: "deposit slot" });
  const recipient = copyBytes(input.recipientCiphertext);
  const bytes = new Uint8Array(HEADER_LENGTH + recipient.length);
  bytes.set(MAGIC);
  bytes[8] = input.slotIndex;
  bytes.set(copyBytes(input.ephemeralPublicKey, 33, "deposit ephemeral key"), 9);
  bytes.set(
    copyBytes(input.ciphertext, HISTORICAL_DEPOSIT_OPENING_LENGTH, "deposit opening ciphertext"),
    42,
  );
  bytes.set(recipient, HEADER_LENGTH);
  return bytes;
}

export function readHistoricalDepositCapsule(
  input: Uint8Array,
): HistoricalDepositCapsule | undefined {
  const bytes = copyBytes(input);
  if (!MAGIC.every((byte, index) => bytes[index] === byte)) return undefined;
  const slotIndex = bytes[8];
  if (
    bytes.length < HEADER_LENGTH ||
    slotIndex === undefined ||
    slotIndex >= HISTORICAL_DEPOSIT_AUDIT_SLOTS
  )
    fail("INTERFACE_CODEC", { field: "deposit capsule" });
  return Object.freeze({
    slotIndex,
    ephemeralPublicKey: bytes.slice(9, 42) as Bytes33,
    ciphertext: bytes.slice(42, HEADER_LENGTH) as Bytes96,
    recipientCiphertext: bytes.slice(HEADER_LENGTH),
  });
}
