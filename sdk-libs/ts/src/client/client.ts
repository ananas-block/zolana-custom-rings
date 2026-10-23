import {
  ZolanaApi,
  resolveClientEndpoints,
  fromClientCause,
  checkedServiceUrl,
  ProverClient,
  checkedContextSlot,
} from "@heliuslabs/zolana/internal";
import {
  initializePoseidon,
  type RequestContext,
  ClientError,
  type ZolanaClientConfig,
} from "@heliuslabs/zolana";
import {
  ZolanaClient,
  type ProofResolution,
  type ProvingKeyReport,
  type Proof,
} from "@heliuslabs/zolana/client";
import type {
  CustomRingBaseProofRequest,
  CustomRingCompressedPolicyProofRequest,
  CustomRingDepositProofRequest,
  CustomRingPolicyProofRequest,
  CustomRingRegisterKeyProofRequest,
} from "./prover/types.js";
import { RingError } from "../ring/error.js";
import { RingIndexer } from "./indexer.js";
import type {
  IndexedDepositClient,
  IndexedDepositInputs,
  IndexedPolicyClient,
  IndexedPolicyInputs,
  RingKeyRegistryEntry,
  RingKeyRegistryReader,
  RingKeyRegistryRegisterProof,
  RingMemberProofRequest,
  RingMemberRequest,
  RingProver,
  RingSpendRecordLookup,
  RingSpendRecordReader,
} from "./ports.js";
import { CustomRingProver } from "./prover/client.js";
import { customRingProof } from "./prover/proof.js";

/** Initializes Poseidon, the constructor alone does not. */
export async function createCustomRingClient(
  config: ZolanaClientConfig = {},
): Promise<CustomRingClient> {
  await initializePoseidon();
  return new CustomRingClient(config);
}

export class CustomRingClient
  extends ZolanaClient
  implements
    RingProver,
    RingKeyRegistryReader,
    RingSpendRecordReader,
    IndexedPolicyClient,
    IndexedDepositClient
{
  readonly #ringProver: CustomRingProver;
  readonly #ringIndexer: RingIndexer;

  constructor(config: ZolanaClientConfig) {
    super(config);
    // The parent's prover keeps one attested session for both rails.
    if (!(this.proofService instanceof ProverClient)) {
      throw new ClientError("CLIENT_INVALID_CONFIG", { details: { field: "proverUrl" } });
    }
    this.#ringProver = new CustomRingProver(this.proofService);
    const endpoints = resolveClientEndpoints(config);
    const url = checkedServiceUrl(
      endpoints.photon,
      endpoints.photonField,
      config.allowInsecureHttp ?? false,
    );
    this.#ringIndexer = new RingIndexer(
      new ZolanaApi({
        url,
        ...(config.apiKey === undefined ? {} : { apiKey: config.apiKey }),
        ...(config.fetch === undefined ? {} : { fetch: config.fetch }),
      }),
    );
  }

  getRingSpendRecord(
    request: RingMemberRequest,
    context?: RequestContext,
  ): Promise<RingSpendRecordLookup> {
    return this.#ringIndexer.getRingSpendRecord(request, context);
  }

  getRingKeyRegistryEntry(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryEntry> {
    return this.#ringIndexer.getRingKeyRegistryEntry(request, context);
  }

  getRingKeyRegistryRegisterProof(
    request: RingMemberProofRequest,
    context?: RequestContext,
  ): Promise<RingKeyRegistryRegisterProof> {
    return this.#ringIndexer.getRingKeyRegistryRegisterProof(request, context);
  }

  proveIndexedRingPolicy(
    inputs: IndexedPolicyInputs,
    context?: RequestContext,
  ): Promise<Readonly<{ proof: Uint8Array; resolution: ProofResolution }>> {
    return proving(async () => {
      const result = await this.#ringProver.proveIndexedPolicy(
        this.#withMinContextSlot(inputs),
        context,
      );
      return Object.freeze({ proof: customRingProof(result.proof), resolution: result.resolution });
    });
  }

  proveIndexedRingDeposit(
    inputs: IndexedDepositInputs,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() =>
      this.#ringProver.proveIndexedDeposit(this.#withMinContextSlot(inputs), context),
    );
  }

  proveCustomRingPolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingPolicy(inputs, context));
  }

  proveCustomRingCompressedPolicy(
    inputs: CustomRingCompressedPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingCompressedPolicy(inputs, context));
  }

  proveCustomRingRegisterKey(
    inputs: CustomRingRegisterKeyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingRegisterKey(inputs, context));
  }

  proveCustomRingDelegatePolicy(
    inputs: CustomRingPolicyProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingDelegatePolicy(inputs, context));
  }

  proveCustomRingBase(
    inputs: CustomRingBaseProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingBase(inputs, context));
  }

  proveCustomRingDeposit(
    inputs: CustomRingDepositProofRequest,
    context?: RequestContext,
  ): Promise<Uint8Array> {
    return provingRing(() => this.#ringProver.proveCustomRingDeposit(inputs, context));
  }

  checkRingProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    return proving(() => this.#ringProver.checkProvingKeys(context));
  }

  /** Mirrors `ZolanaClient`'s own floor, `indexerConfig.requireSlot`. */
  #withMinContextSlot<T extends Readonly<{ minContextSlot?: bigint }>>(inputs: T): T {
    const requested = checkedContextSlot(inputs.minContextSlot);
    const required = this.indexerConfig.requireSlot;
    return required === undefined || (requested !== undefined && requested >= required)
      ? inputs
      : { ...inputs, minContextSlot: required };
  }
}

async function proving<T>(run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (cause) {
    throw cause instanceof RingError ? cause : fromClientCause(cause);
  }
}

function provingRing(run: () => Promise<Proof>): Promise<Uint8Array> {
  return proving(async () => customRingProof(await run()));
}
