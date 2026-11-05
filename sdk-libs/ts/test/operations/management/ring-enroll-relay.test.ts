import {
  addressBytes,
  compileUnsignedTransaction,
  encodeBase58,
  treeAddress,
} from "@heliuslabs/zolana/internal";
import type { Instruction } from "@heliuslabs/zolana/interface";
import {
  createKeyPairSignerFromPrivateKeyBytes,
  getBase58Encoder,
  getBase64Decoder,
  verifySignature,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { ringComputeUnitLimit } from "../../../src/operations/management/admin.js";
import { enrollCredentialInstruction } from "../../../src/operations/management/enrollment.js";
import { prepareEnrollRelay } from "../../../src/operations/management/enroll-relay.js";
import { SIZE_PROBE_LIFETIME } from "../../../src/operations/workflow/compile.js";
import type { AuditCredential } from "../../../src/protocol/membership/credential.js";
import { memberOfTag } from "../../../src/protocol/membership/policy.js";
import {
  relayEnrollInstruction,
  type RelayEnrollInputs,
} from "../../../src/protocol/ring-rpc/relay-enroll-inputs.js";
import { RingInstructionTag } from "../../../src/protocol/transaction/instruction-tag.js";
import type { RelayStatus } from "../../../src/protocol/ring-rpc/ring-rpc-types.js";
import { PendingRelaySignature, type RingRelayClient } from "../../../src/rpc/relay.js";
import { filled } from "../../helpers/ring-pipeline.js";

const address = (byte: number): Address => encodeBase58(new Uint8Array(32).fill(byte)) as Address;
const FEE_PAYER = address(0x44);
const OUTPUT_TREE = treeAddress(3);
const quote = { feePayer: FEE_PAYER, validUntilSlot: 100n };
const ownerSigner = () => createKeyPairSignerFromPrivateKeyBytes(new Uint8Array(32).fill(1));

function inputsOf(owner: Address): RelayEnrollInputs {
  return {
    ringProgramId: address(0x90),
    owner,
    outputTree: OUTPUT_TREE,
    instructionData: Uint8Array.of(RingInstructionTag.enroll, 1, 2),
  };
}

function messageOf(instruction: Instruction): Uint8Array {
  const { messageBytes } = compileUnsignedTransaction({
    feePayer: FEE_PAYER,
    lifetime: SIZE_PROBE_LIFETIME,
    instructions: [instruction],
    computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.enroll),
  });
  return new Uint8Array(messageBytes);
}

function relayAnswering(message: Uint8Array, relayId: string) {
  return {
    getRelayQuote: vi.fn(),
    getRelayStatus: vi.fn(),
    prepareRelay: vi.fn(async () => ({
      step: "signMessage",
      relayId,
      message: getBase64Decoder().decode(message),
    })),
    submitRelay: vi.fn(async (): Promise<RelayStatus> => ({ status: "awaitingSignature" })),
  } as unknown as RingRelayClient;
}

async function signed(answer: (honest: Instruction) => Instruction) {
  const owner = await ownerSigner();
  const inputs = inputsOf(owner.address);
  const prepared = await prepareEnrollRelay({ inputs, owner, quote });
  const message = messageOf(answer(await relayEnrollInstruction(inputs, FEE_PAYER)));
  const relay = relayAnswering(message, prepared.relayId());
  const pending = await prepared.send(relay);
  if (!(pending instanceof PendingRelaySignature)) throw new Error("the owner signs");
  return pending.sign(relay, owner);
}

const refused = (mismatch: string) => ({
  code: "RING_RELAY_MESSAGE_INVALID",
  details: { mismatch },
});

describe("relayed enrollment", () => {
  it("signs the enrollment the owner proved with its real key", async () => {
    const owner = await ownerSigner();
    const inputs = inputsOf(owner.address);
    const prepared = await prepareEnrollRelay({ inputs, owner, quote });
    const message = messageOf(await relayEnrollInstruction(inputs, FEE_PAYER));
    const relay = relayAnswering(message, prepared.relayId());
    const pending = await prepared.send(relay);
    if (!(pending instanceof PendingRelaySignature)) throw new Error("the owner signs");
    await expect(pending.sign(relay, owner)).resolves.toEqual({ status: "awaitingSignature" });
    const signature = vi.mocked(relay.submitRelay).mock.calls[0]?.[0].signature;
    expect(
      await verifySignature(
        owner.keyPair.publicKey,
        new Uint8Array(getBase58Encoder().encode(signature as string)) as never,
        message,
      ),
    ).toBe(true);
  });

  it("names the accounts the enroll instruction names", async () => {
    const owner = await ownerSigner();
    const credential: AuditCredential = {
      ringId: filled(1),
      member: memberOfTag(addressBytes(owner.address)),
      nullifierPk: filled(2),
      listTag: filled(3),
      auditorPubkey: new Uint8Array(33).fill(4) as AuditCredential["auditorPubkey"],
      ephU: filled(5),
      ciphertext: new Uint8Array(64).fill(6) as AuditCredential["ciphertext"],
    };
    const built = await enrollCredentialInstruction({
      ringProgramId: address(0x90),
      owner: owner.address,
      payer: FEE_PAYER,
      outputTreeId: 3,
      proven: { credential, registerKey: new Uint8Array(192) },
      write: {
        transact: {
          a: filled(7),
          b: new Uint8Array(128) as never,
          c: filled(8),
        },
        addressRootIndex: 2,
      },
    });
    const relayed = await relayEnrollInstruction(inputsOf(owner.address), FEE_PAYER);
    expect(relayed.accounts).toEqual(built.accounts);
    expect(relayed.programAddress).toBe(built.programAddress);
  });

  it("refuses a swapped account with Accounts", async () => {
    await expect(
      signed((honest) => ({
        ...honest,
        accounts: (honest.accounts ?? []).map((meta) =>
          meta.address === OUTPUT_TREE ? { ...meta, address: treeAddress(4) } : meta,
        ),
      })),
    ).rejects.toMatchObject(refused("Accounts"));
  });

  it("refuses a changed byte with Data", async () => {
    await expect(
      signed((honest) => {
        const data = Uint8Array.from(honest.data ?? []);
        data[1] = (data[1] ?? 0) ^ 1;
        return { ...honest, data };
      }),
    ).rejects.toMatchObject(refused("Data"));
  });

  it("refuses another program", async () => {
    await expect(
      signed((honest) => ({ ...honest, programAddress: address(0x57) })),
    ).rejects.toMatchObject(refused("Program"));
  });

  it("refuses an owner that is not the signer", async () => {
    const owner = await ownerSigner();
    await expect(
      prepareEnrollRelay({ inputs: inputsOf(address(9)), owner, quote }),
    ).rejects.toMatchObject(refused("Signer"));
  });
});
