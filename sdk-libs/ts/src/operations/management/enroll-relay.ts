import { getBase58Decoder, getBase64Decoder, type MessagePartialSigner } from "@solana/kit";
import type { RequestContext, Signature } from "@heliuslabs/zolana/interface";
import { treeAddress } from "@heliuslabs/zolana/internal";

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

/** Rust `Enroll::prepare_relay`, the relayed message carries `Enroll` and never `REGISTER`. */
export async function prepareEnrollmentRelay(
  input: Omit<Parameters<typeof prepareEnrollment>[0], "owner" | "payer"> &
    Readonly<{ owner: MessagePartialSigner; quote: RelayQuote }>,
  context?: RequestContext,
): Promise<PreparedRelay> {
  const { owner, quote, ringProgramId, outputTreeId } = input;
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
