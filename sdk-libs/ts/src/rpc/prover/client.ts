import type { ProverClient } from "@heliuslabs/zolana/internal";
import { parseCheckedProof } from "@heliuslabs/zolana/internal";
import type { RequestContext } from "@heliuslabs/zolana";
import type { Proof, ProvingKeyReport } from "@heliuslabs/zolana/client";

import { RING_PROVING_KEY_SHA256S } from "../../protocol/proof/proving-keys.js";
import { ringProofRequestBody, ringRequestKey, type RingProofRequest } from "./ring.js";

export class CustomRingProver {
  readonly #prover: ProverClient;

  constructor(prover: ProverClient) {
    this.#prover = prover;
  }

  async proveRing(request: RingProofRequest, context?: RequestContext): Promise<Proof> {
    const key = ringRequestKey(request);
    const body = JSON.stringify(ringProofRequestBody(request));
    return parseCheckedProof(await this.#prover.send(body, "queued", key, context), key);
  }

  checkProvingKeys(context?: RequestContext): Promise<ProvingKeyReport> {
    return this.#prover.checkProvingKeys(context, RING_PROVING_KEY_SHA256S);
  }
}
