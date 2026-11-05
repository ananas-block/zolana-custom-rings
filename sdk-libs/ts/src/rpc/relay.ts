/** The Ring RPC relay a wallet sends its transfer through, Rust `relay`. */
import type { WalletUtxo } from "@heliuslabs/zolana/transaction";
import {
  type Address,
  getBase58Decoder,
  getBase64Encoder,
  type TransactionPartialSigner,
} from "@solana/kit";

import type { RequestContext } from "@heliuslabs/zolana/interface";
import { concatBytes, indexerScalars, sha256 } from "@heliuslabs/zolana/internal";
import type { indexerTypes } from "@heliuslabs/zolana/internal";

import { RingError } from "../protocol/error.js";
import type { ApprovalOpening } from "../protocol/membership/approval-totals.js";
import {
  encodePrepareAuthorityTransferRequest,
  encodePrepareRelayRequest,
} from "../protocol/ring-rpc/ring-rpc-codec.js";
import type {
  PrepareAuthorityTransferRequest,
  PrepareRelayRequest,
  RelayStatus,
  RelayStep,
} from "../protocol/ring-rpc/ring-rpc-types.js";
import {
  checkRelayMessage,
  expectedPublicOwner,
  type RelayFunderTerms,
  type RelayTransferTerms,
  type DelegateRingConfig,
  type ExpectedRelayMessage,
  expectedDelegate,
  mismatch,
  type RequestedAuthorityTransfer,
  type VerifiedRelayMessage,
} from "./relay-message.js";
import type { RingRpc } from "./ring-rpc.js";

type Hash = indexerTypes.Hash;

const RELAY_DOMAIN = new TextEncoder().encode("zolana/ring-rpc-relay");
const base58 = getBase58Decoder();
const base64 = getBase64Encoder();

/** Rust `RingRelay`. */
export type RingRelayClient = Pick<
  RingRpc,
  "getRelayQuote" | "prepareRelay" | "submitRelay" | "getRelayStatus"
>;

/** Rust `RingRelay`, the calls an authority transfer makes. */
export type RingAuthorityRelayClient = Pick<RingRpc, "prepareAuthorityTransfer" | "submitRelay">;

/** Rust `PrepareRelayRequest::relay_id`, a retried request names the same relay. */
export function relayId(request: PrepareRelayRequest): Hash {
  return wireRelayId(encodePrepareRelayRequest(request));
}

function wireRelayId(wire: Readonly<Record<string, unknown>>): Hash {
  const bytes = new TextEncoder().encode(JSON.stringify(wire));
  return indexerScalars.checkedHash(
    base58.decode(sha256(concatBytes(RELAY_DOMAIN, bytes))),
    "relayId",
  );
}

/** Rust `PreparedRelay`. */
export class PreparedRelay {
  readonly request: PrepareRelayRequest;
  /** `undefined` on the rails that sign inside the proof. */
  readonly #expected: ExpectedRelayMessage | undefined;

  /** @internal */
  constructor(request: PrepareRelayRequest, expected?: ExpectedRelayMessage) {
    this.request = request;
    this.#expected = expected;
    Object.freeze(this);
  }

  relayId(): Hash {
    return relayId(this.request);
  }

  async send(relay: RingRelayClient, context?: RequestContext): Promise<RelaySent> {
    const step = await relay.prepareRelay(this.request, context);
    return accepted({ step, relayId: this.relayId(), expected: this.#expected });
  }
}

/** Rust `PreparedAuthorityTransfer`, the delegate signs only a message the quoted fee payer pays. */
export class PreparedAuthorityTransfer {
  readonly request: PrepareAuthorityTransferRequest;
  readonly #requested: RequestedAuthorityTransfer;

  /** Rust `RequestedAuthorityTransfer::prepare`, refuses an allowed set built for other sources. */
  constructor(requested: RequestedAuthorityTransfer) {
    requested.allowed.checkSources(requested.request.transfer.sources);
    this.request = requested.request;
    this.#requested = requested;
    Object.freeze(this);
  }

  /** Rust `PrepareAuthorityTransferRequest::relay_id`. */
  relayId(): Hash {
    return wireRelayId(encodePrepareAuthorityTransferRequest(this.request));
  }

  async send(relay: RingAuthorityRelayClient, context?: RequestContext): Promise<RelaySent> {
    const expected = await expectedDelegate(this.#requested);
    const step = await relay.prepareAuthorityTransfer(this.request, context);
    return accepted({ step, relayId: this.relayId(), expected });
  }
}

function accepted({
  step,
  relayId,
  expected,
}: Readonly<{
  step: RelayStep;
  relayId: Hash;
  expected: ExpectedRelayMessage | undefined;
}>): RelaySent {
  if (step.relayId !== relayId) throw new RingError("RING_RELAY_ID_MISMATCH");
  if (step.step === "submitted") return Object.freeze({ step: "submitted", relayId });
  return new PendingRelaySignature(relayId, base64.encode(step.message) as Uint8Array, expected);
}

/** Rust `RelaySent`, a `signMessage` step waits for its signer. */
export type RelaySent = Readonly<{ step: "submitted"; relayId: Hash }> | PendingRelaySignature;

/** Rust `RelaySent::submitted`, a public signature would name the hidden owner. */
export function submittedRelay(sent: RelaySent): Hash {
  if (sent instanceof PendingRelaySignature) throw new RingError("RING_RELAY_OWNER_SIGNATURE");
  return sent.relayId;
}

/** Rust `PendingSignature`. */
export class PendingRelaySignature {
  readonly step = "signMessage";
  readonly relayId: Hash;
  readonly #message: Uint8Array;
  readonly #expected: ExpectedRelayMessage | undefined;

  /** @internal */
  constructor(relayId: Hash, message: Uint8Array, expected?: ExpectedRelayMessage) {
    this.relayId = relayId;
    this.#message = message.slice();
    this.#expected = expected;
    Object.freeze(this);
  }

  /** What the wallet sealed for one public owner, an outside co-signer holds none. */
  transferTerms(signer: Address): RelayTransferTerms | undefined {
    if (this.#expected?.kind === "sealed")
      return this.#expected.terms.find((terms) => terms.signer === signer);
    return this.#expected?.kind === "publicOwner" && this.#expected.terms.signer === signer
      ? this.#expected.terms
      : undefined;
  }

  /** What the wallet sealed for one public funder of a deposit leg. */
  funderTerms(signer: Address): RelayFunderTerms | undefined {
    if (this.#expected?.kind === "sealed")
      return this.#expected.funders?.find((terms) => terms.signer === signer);
    return this.#expected?.kind === "funder" && this.#expected.terms.signer === signer
      ? this.#expected.terms
      : undefined;
  }

  /** What opens the sealed frame's digest, for the wallet to hand to its co-signer, Rust `approval_opening`. */
  approvalOpening(): ApprovalOpening | undefined {
    return this.#expected?.kind === "sealed" ? this.#expected.approval : undefined;
  }

  /** Rust `PendingSignature::verify`, the expectation comes from the wallet's own request. */
  verify(signer: Address): VerifiedRelayMessage {
    if (this.#expected === undefined) throw mismatch("Unrequested");
    return checkRelayMessage(this.#expected, this.#message, signer);
  }

  async sign(
    relay: RingRelayClient,
    signer: TransactionPartialSigner,
    context?: RequestContext,
  ): Promise<RelayStatus> {
    return this.#submit(relay, this.verify(signer.address), signer, context);
  }

  async #submit(
    relay: RingRelayClient,
    verified: VerifiedRelayMessage,
    signer: TransactionPartialSigner,
    context: RequestContext | undefined,
  ): Promise<RelayStatus> {
    const signature = await verified.sign(signer, context);
    return relay.submitRelay(
      { relayId: this.relayId, signer: verified.signer, signature },
      context,
    );
  }
}

/** The notes are required, the owner's signature is the only gate on them. */
export class OwnerApproval {
  readonly #input: OwnerApprovalInput;

  constructor(input: OwnerApprovalInput) {
    this.#input = input;
    Object.freeze(this);
  }

  async pending(): Promise<PendingRelaySignature> {
    const { relayId, message, terms, config, knownNotes } = this.#input;
    return new PendingRelaySignature(
      relayId,
      message,
      await expectedPublicOwner({ terms, config, knownNotes }),
    );
  }
}

export interface OwnerApprovalInput {
  readonly relayId: Hash;
  readonly message: Uint8Array;
  readonly terms: RelayTransferTerms;
  readonly config: DelegateRingConfig;
  /** Every note the wallet holds, the nullifiers are the wallet's own derivation. */
  readonly knownNotes: readonly Pick<WalletUtxo, "nullifier">[];
}
