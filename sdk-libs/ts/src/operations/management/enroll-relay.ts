import { getBase58Decoder, getBase64Decoder, type MessagePartialSigner } from "@solana/kit";
import type { RequestContext, Signature } from "@heliuslabs/zolana/interface";
import { fetchUserRecord, treeAddress } from "@heliuslabs/zolana/internal";

import { RingError } from "../../protocol/error.js";
import {
  encodeRelayEnrollInputs,
  enrollRequestDigest,
  type RelayEnrollInputs,
} from "../../protocol/ring-rpc/relay-enroll-inputs.js";
import type { RelayIntent, RelayQuote } from "../../protocol/ring-rpc/ring-rpc-types.js";
import { expectedEnroll, mismatch } from "../../rpc/relay-message.js";
import { PreparedRelay } from "../../rpc/relay.js";
import { signMessage } from "../../rpc/ring-rpc.js";
import { prepareEnrollment } from "./enrollment.js";

/** A PDA holds no key to sign here, its program enrolls through CPI. */
export async function prepareEnrollRelay(
  input: Readonly<{
    inputs: RelayEnrollInputs;
    owner: MessagePartialSigner;
    quote: RelayQuote;
  }>,
): Promise<PreparedRelay> {
  const { inputs, owner, quote } = input;
  if (owner.address !== inputs.owner) throw mismatch("Signer");
  const signature = await signMessage(owner, enrollRequestDigest(inputs));
  const intent: RelayIntent = {
    operation: "enroll",
    proofInputs: getBase64Decoder().decode(encodeRelayEnrollInputs(inputs)) as never,
    ownerSignature: getBase58Decoder().decode(signature) as Signature,
  };
  return new PreparedRelay(
    { ring: inputs.ringProgramId, quote, intent },
    await expectedEnroll(inputs, quote.feePayer),
  );
}

/** Rust `Enroll::prepare_relay`, the quoted fee payer funds `Enroll` alone. */
export async function prepareEnrollmentRelay(
  input: Omit<Parameters<typeof prepareEnrollment>[0], "owner" | "payer"> &
    Readonly<{ owner: MessagePartialSigner; quote: RelayQuote }>,
  context?: RequestContext,
): Promise<PreparedRelay> {
  const { owner, quote, ringProgramId, outputTreeId } = input;
  // The relay funds no record rent, a missing record refuses before any proof.
  if ((await fetchUserRecord({ rpc: input.client, owner: owner.address }, context)) === undefined)
    throw new RingError("RING_RELAY_NEEDS_USER_RECORD", { details: { owner: owner.address } });
  const prepared = await prepareEnrollment(
    { ...input, owner: owner.address, payer: quote.feePayer },
    context,
  );
  return prepareEnrollRelay({
    inputs: {
      ringProgramId,
      owner: owner.address,
      outputTree: treeAddress(outputTreeId),
      instructionData: new Uint8Array(prepared.enroll.data ?? []),
    },
    owner,
    quote,
  });
}
