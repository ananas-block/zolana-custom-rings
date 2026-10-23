import type { MethodDescriptor } from "@heliuslabs/zolana/internal";

import {
  decodeRingKeyRegistryEntry,
  decodeRingKeyRegistryRegisterProof,
  decodeRingSpendRecordResponse,
  encodeRingMemberProofRequest,
  encodeRingMemberRequest,
} from "./codec.js";
import type {
  GetRingSpendRecordResponse,
  RingKeyRegistryEntry,
  RingKeyRegistryRegisterProof,
  RingMemberProofRequest,
  RingMemberRequest,
} from "./types.js";

export const getRingSpendRecordMethod: MethodDescriptor<
  RingMemberRequest,
  GetRingSpendRecordResponse
> = {
  name: "getRingSpendRecord",
  encodeRequest: encodeRingMemberRequest,
  decodeResponse: decodeRingSpendRecordResponse,
};
export const getRingKeyRegistryEntryMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingKeyRegistryEntry
> = {
  name: "getRingKeyRegistryEntry",
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingKeyRegistryEntry,
};
export const getRingKeyRegistryRegisterProofMethod: MethodDescriptor<
  RingMemberProofRequest,
  RingKeyRegistryRegisterProof
> = {
  name: "getRingKeyRegistryRegisterProof",
  encodeRequest: encodeRingMemberProofRequest,
  decodeResponse: decodeRingKeyRegistryRegisterProof,
};
