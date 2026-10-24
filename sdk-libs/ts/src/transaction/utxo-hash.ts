/** SPP UTXO commitments over field values a ring reads from a disclosure, pinned SPP layout. */
import type { Address, Bytes32 } from "@heliuslabs/zolana";
import {
  checked,
  checkU64,
  commitmentPoseidon,
  decodeAddress,
  hashBytes,
  rightAlign,
  ZERO_32,
} from "@heliuslabs/zolana/internal";
import { DUMMY_DOMAIN, treeIdField, UTXO_DOMAIN } from "@heliuslabs/zolana/interface";
import { TransactionError, type TreeId } from "@heliuslabs/zolana/transaction";

interface CommitmentFields {
  readonly owner: Bytes32;
  readonly amount: bigint;
  readonly blinding: Bytes32;
  readonly treeId: TreeId;
  readonly dataHash?: Bytes32;
  readonly ringDataHash?: Bytes32;
}

/** A ring commitment under the ring id field, `hashBytes` of the ring program id. */
export type RingIdCommitmentInput = CommitmentFields & {
  readonly asset: Address;
  readonly ringId: Bytes32;
};

/** A commitment of field values, `assetField` the `hashBytes` of a mint no registry may know. */
export type FieldCommitmentInput = CommitmentFields & {
  readonly assetField: Bytes32;
  readonly ringId: Bytes32;
};

export function ringIdUtxoHash(input: RingIdCommitmentInput): Bytes32 {
  return commitment(input, hashBytes(decodeAddress(input.asset)) as Bytes32);
}

export function fieldUtxoHash(input: FieldCommitmentInput): Bytes32 {
  return commitment(input, checked<Bytes32>(input.assetField, 32, "asset field"));
}

/** The dummy commitment, its tree id and blinding over zeros. */
export function dummyUtxoHash(treeId: TreeId, blinding: Bytes32): Bytes32 {
  return commitmentPoseidon([
    rightAlign(Uint8Array.of(DUMMY_DOMAIN)),
    treeIdField(checkedTreeId(treeId)),
    ZERO_32,
    ZERO_32,
    ZERO_32,
    commitmentPoseidon([ZERO_32, ZERO_32]),
    commitmentPoseidon([ZERO_32, checked<Bytes32>(blinding, 32, "blinding")]),
  ]);
}

function commitment(
  input: CommitmentFields & { readonly ringId: Bytes32 },
  asset: Bytes32,
): Bytes32 {
  const amount = new Uint8Array(8);
  new DataView(amount.buffer).setBigUint64(0, checkU64(input.amount, "amount"), false);
  const ringDataHash = input.ringDataHash
    ? checked<Bytes32>(input.ringDataHash, 32, "ring data hash")
    : ZERO_32;
  return commitmentPoseidon([
    rightAlign(Uint8Array.of(UTXO_DOMAIN)),
    treeIdField(checkedTreeId(input.treeId)),
    asset,
    rightAlign(amount),
    input.dataHash ? checked<Bytes32>(input.dataHash, 32, "data hash") : ZERO_32,
    commitmentPoseidon([ringDataHash, checked<Bytes32>(input.ringId, 32, "ring id")]),
    commitmentPoseidon([
      checked<Bytes32>(input.owner, 32, "owner hash"),
      checked<Bytes32>(input.blinding, 32, "blinding"),
    ]),
  ]);
}

function checkedTreeId(treeId: TreeId): TreeId {
  if (!Number.isInteger(treeId) || treeId < 0 || treeId > 0xffff) {
    throw new TransactionError("TRANSACTION_INVALID_TREE_ID", { treeId });
  }
  return treeId;
}
