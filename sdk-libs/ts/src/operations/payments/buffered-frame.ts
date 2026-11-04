/** Rust `operations::buffered`. */
import { getProgramDerivedAddress } from "@solana/kit";
import type { Address, Bytes32, Instruction } from "@heliuslabs/zolana/interface";
import {
  addressBytes,
  instruction,
  meta,
  signerAddress,
  SYSTEM_PROGRAM,
  type SignerAccount,
} from "@heliuslabs/zolana/internal";
import { TRANSACTION_SIZE_LIMIT } from "@heliuslabs/zolana/interface";

import { RingError } from "../../protocol/error.js";
import {
  closeFrameBufferData,
  FRAME_BUFFER_PDA_SEED,
  frameDigest,
  MAX_FRAME_LEN,
  settleBufferedData,
  writeFrameData,
} from "../../protocol/transaction/frame-buffer.js";
import { RingInstructionTag } from "../../protocol/transaction/instruction-tag.js";
import { ringComputeUnitLimit } from "../management/admin.js";
import { transactionSize } from "../workflow/compile.js";

/** One proven inline transfer as its buffered instructions, its payer the writer. */
export class BufferedFrame {
  readonly buffer: Address;
  readonly #ringProgram: Address;
  readonly #writer: SignerAccount;
  readonly #nonce: bigint;
  readonly #digest: Bytes32;
  readonly #frame: Uint8Array;
  readonly #inner: NonNullable<Instruction["accounts"]>;

  private constructor(
    fields: Readonly<{
      buffer: Address;
      inline: Instruction;
      frame: Uint8Array;
      writer: SignerAccount;
      nonce: bigint;
    }>,
  ) {
    this.buffer = fields.buffer;
    this.#ringProgram = fields.inline.programAddress;
    this.#writer = fields.writer;
    this.#nonce = fields.nonce;
    this.#digest = frameDigest(fields.frame);
    this.#frame = fields.frame;
    this.#inner = fields.inline.accounts ?? [];
    Object.freeze(this);
  }

  /** `inline` is the transfer as it would send without a buffer. */
  static async of(
    inline: Instruction,
    writer: SignerAccount,
    nonce: bigint,
  ): Promise<BufferedFrame> {
    if (BigInt.asUintN(64, nonce) !== nonce) throw new RingError("RING_BUFFERED_NONCE");
    const frame = Uint8Array.from(inline.data ?? []);
    if (frame.length > MAX_FRAME_LEN)
      throw new RingError("RING_FRAME_TOO_LARGE", {
        details: { bytes: frame.length, limit: MAX_FRAME_LEN },
      });
    if (frame[0] !== RingInstructionTag.transfer) throw new RingError("RING_BUFFERED_TAG");
    const seedNonce = new Uint8Array(8);
    new DataView(seedNonce.buffer).setBigUint64(0, nonce, true);
    const [buffer] = await getProgramDerivedAddress({
      programAddress: inline.programAddress,
      seeds: [FRAME_BUFFER_PDA_SEED, addressBytes(signerAddress(writer)), seedNonce],
    });
    return new BufferedFrame({ buffer, inline, frame, writer, nonce });
  }

  /** In offset order, the first creates the buffer at the frame's full length. */
  writes(): readonly Instruction[] {
    const empty = transactionSize({
      feePayer: signerAddress(this.#writer),
      instructions: [this.#write(0, new Uint8Array())],
      computeUnitLimit: ringComputeUnitLimit(RingInstructionTag.writeFrame),
    });
    const chunk = Math.max(TRANSACTION_SIZE_LIMIT - empty.bytes, 1);
    return Array.from({ length: Math.ceil(this.#frame.length / chunk) }, (_, index) =>
      this.#write(index * chunk, this.#frame.subarray(index * chunk, (index + 1) * chunk)),
    );
  }

  /** Every signer signs the frame's digest, the program closes the buffer into the writer. */
  settle(): Instruction {
    return instruction(
      settleBufferedData(this.#digest),
      [meta(this.buffer, false, true), meta(this.#ringProgram, false, false), ...this.#inner],
      this.#ringProgram,
    );
  }

  /** Abandons an unsettled buffer, its rent returns to the writer. */
  close(): Instruction {
    return instruction(
      closeFrameBufferData(),
      [
        meta(this.#writer, true, true),
        meta(this.buffer, false, true),
        meta(this.#writer, true, true),
      ],
      this.#ringProgram,
    );
  }

  #write(offset: number, bytes: Uint8Array): Instruction {
    return instruction(
      writeFrameData({ nonce: this.#nonce, frameLen: this.#frame.length, offset, bytes }),
      [
        meta(this.#writer, true, true),
        meta(this.buffer, false, true),
        meta(SYSTEM_PROGRAM, false, false),
      ],
      this.#ringProgram,
    );
  }
}
