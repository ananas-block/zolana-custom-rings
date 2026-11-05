// Package audit proves what a ring auditor reads from a ring transfer.
//
// A statement built on the package proves the following.
//  1. The stream is AES-256-CTR under a key schedule bound to the auditor key, tx_u and the salt,
//     over the sealed tx_viewing_sk, R, the entry evidence, one record per slot and one tail per slot.
//  2. Each live slot's record and tail hold the opening its published commitment hashes, and a
//     published slot's blinding derives from the sealed key. The auditor rebuilds every commitment
//     from the stream and the frame.
//  3. R counts the spent notes among the published inputs, and a default-ring input opens in the
//     entry evidence.
//
// It proves nothing about a recipient's body or tag, delivery stays outside the circuit.
package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingProgramID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingProgramID frontend.Variable
	TxViewingSk   [32]frontend.Variable
	AuditorPk     [32]frontend.Variable
	Salt          [16]frontend.Variable
	Layout        frontend.Variable
}

type Envelope struct {
	txViewingSk [32]frontend.Variable
	// txPk is pack_be(0x04 ‖ tx_u).
	txPk       [2]frontend.Variable
	salt       frontend.Variable
	outputSeed frontend.Variable
}

func (w AuditWires) OpenEnvelope(api frontend.API, rc frontend.Rangechecker) Envelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_viewing_sk, the generator bounds every secret byte the packings read.
	txPk := shared.PackedKey(api, x25519.ScalarMulGenerator(api, w.TxViewingSk))
	packedTxViewingSk := [2]frontend.Variable(shared.PackBounded(api, w.TxViewingSk[:]))
	return Envelope{
		txViewingSk: w.TxViewingSk,
		txPk:        [2]frontend.Variable(txPk),
		salt:        salt,
		outputSeed:  transaction.DeriveOutputBlindingSeed(api, w.FirstNullifier, shared.BlindingSeed(api, packedTxViewingSk, salt)),
	}
}

// StreamRanges mirrors AuditStreamLayout in program-libs/interface/src/proof/audit_stream.rs.
type StreamRanges struct {
	StreamShape
}

const (
	streamBlockLen = 16
	// StreamFirstCounter is aes.Cipher.CTREncrypt's first counter, mirrored by STREAM_FIRST_COUNTER.
	StreamFirstCounter  = 2
	EnvelopeKeyLen      = 32
	RealInputCountLen   = 1
	DefaultInputBitsLen = 8
	fieldLen            = 32
	amountLen           = 8
	kindLen             = 1
	// RecordLen is the bytes a transfer frame carries, mirrored by AUDIT_RECORD_LEN.
	RecordLen = kindLen + amountLen + 3*fieldLen
	TailLen   = 2 * fieldLen
	// EntryInputLen mirrors ENTRY_INPUT_LEN.
	EntryInputLen = amountLen + 6*fieldLen
	RecordBlocks  = (RecordLen + streamBlockLen - 1) / streamBlockLen
	// RecordStride mirrors RECORD_STRIDE, slot i keeps its counter and a transfer frame omits the padding.
	RecordStride = RecordBlocks * streamBlockLen
	TailBlocks   = TailLen / streamBlockLen
)

func (s StreamShape) Ranges() StreamRanges {
	return StreamRanges{StreamShape: s}
}

func (r StreamRanges) EnvelopeHeadLen() int {
	if r.Entry {
		return EnvelopeKeyLen + RealInputCountLen + DefaultInputBitsLen
	}
	return EnvelopeKeyLen + RealInputCountLen
}

func (r StreamRanges) entryLen() int {
	if r.Entry {
		return EntryInputLen
	}
	return 0
}

// EnvelopeLen is what the frame carries, with no padding.
func (r StreamRanges) EnvelopeLen(count int) int {
	return r.EnvelopeHeadLen() + count*r.entryLen()
}

// EnvelopeBlocks is fixed per shape, no published count moves a record's counter.
func (r StreamRanges) EnvelopeBlocks() int {
	return (r.EnvelopeLen(r.InputClass) + streamBlockLen - 1) / streamBlockLen
}

// RecordCounter must match the readers, another counter decrypts noise.
func (r StreamRanges) RecordCounter(i int) int {
	return StreamFirstCounter + r.EnvelopeBlocks() + i*RecordBlocks
}

// TailCounter must match the readers, a tail shares no counter with a record.
func (r StreamRanges) TailCounter(i int) int {
	return r.RecordCounter(r.Outputs) + i*TailBlocks
}

// CapacityBlocks covers every slot the key serves, a dataless key has no tail region.
func (r StreamRanges) CapacityBlocks() int {
	blocks := r.EnvelopeBlocks() + r.Outputs*RecordBlocks
	if r.Data {
		blocks += r.Outputs * TailBlocks
	}
	return blocks
}

func (r StreamRanges) RecordOffset(i int) int {
	return (r.RecordCounter(i) - StreamFirstCounter) * streamBlockLen
}

func (r StreamRanges) TailOffset(i int) int {
	return (r.TailCounter(i) - StreamFirstCounter) * streamBlockLen
}

type Stream struct {
	ranges StreamRanges
	sealed shared.Sealed
	digest frontend.Variable
	// RecordChain hashes every published record's ciphertext, zero past m.
	RecordChain frontend.Variable
	// TailChain hashes every published tail's ciphertext, zero while has_data is clear.
	TailChain frontend.Variable
	// RealInputs is the sealed R, the count of spent notes.
	RealInputs frontend.Variable
	NoSpend    frontend.Variable
}

// SealStream mirrors AuditEnvelope::encode and the record layout in program-libs/interface/src/proof/audit_stream.rs.
func (w AuditWires) SealStream(api frontend.API, rc frontend.Rangechecker, e Envelope, shape StreamShape, opened Opened, spent SpentInputs) Stream {
	ranges := shape.Ranges()
	evidence := spent.evidence(api, rc, ranges)
	plaintext := slices.Concat(w.TxViewingSk[:], evidence.head, slices.Concat(evidence.entries...))
	// The envelope's padding ends on the block before R0, the longest evidence never reaches a record's counter.
	plaintext = append(plaintext, shared.Zeros(ranges.EnvelopeBlocks()*streamBlockLen-len(plaintext))...)
	// A record holds its blocks alone, a counter serving two regions reveals the XOR of their plaintexts.
	plaintext = slices.Concat(plaintext, slices.Concat(opened.records...), slices.Concat(opened.tails...))
	// A plaintext off its ranges moves every record off the counters the readers use.
	if len(plaintext) != ranges.CapacityBlocks()*streamBlockLen {
		panic("audit: the stream plaintext differs from its ranges")
	}
	// One key expansion and nonce cover every block, the cipher's tables bound every plaintext and ciphertext byte.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: w.TxViewingSk, AuditorPk: w.AuditorPk, Info: shared.AuditEncInfo}.SealSalted(api, e.txPk[:], e.salt)
	return Stream{
		ranges:      ranges,
		sealed:      sealed,
		digest:      countedDigest(api, sealed.Ciphertext, EnvelopeKeyLen+len(evidence.head), ranges.entryLen(), spent.Count),
		RecordChain: gadget.HashChain4(api, SlotRegions{Start: ranges.RecordOffset(0), Stride: RecordStride, Length: RecordLen}.Hashes(api, sealed.Ciphertext, opened.Count.Active)),
		TailChain:   tailChain(api, sealed.Ciphertext, ranges, opened),
		RealInputs:  evidence.realInputs,
		NoSpend:     api.IsZero(evidence.realInputs),
	}
}

// SlotRegions locates one ciphertext region per slot inside a sealed stream.
type SlotRegions struct {
	Start, Stride, Length int
}

// Hashes is hash_bytes(region_i) per slot, zero while the slot's flag is clear, the one form every statement binds a slot's ciphertext in.
func (r SlotRegions) Hashes(api frontend.API, ciphertext, active []frontend.Variable) []frontend.Variable {
	hashes := make([]frontend.Variable, len(active))
	for i, flag := range active {
		offset := r.Start + i*r.Stride
		hashes[i] = api.Mul(flag, gadget.HashBoundedBytes(api, ciphertext[offset:offset+r.Length]))
	}
	return hashes
}

func tailChain(api frontend.API, ciphertext []frontend.Variable, ranges StreamRanges, opened Opened) frontend.Variable {
	if !ranges.Data {
		return 0
	}
	// A clear has_data transmits no tail, the program binds zero.
	return api.Mul(opened.hasData, gadget.HashChain4(api, SlotRegions{Start: ranges.TailOffset(0), Stride: TailLen, Length: TailLen}.Hashes(api, ciphertext, opened.Count.Active)))
}

// countedDigest mirrors ciphertext_digest in program-libs/interface/src/proof/statement.rs over the head and the count's entries.
func countedDigest(api frontend.API, ciphertext []frontend.Variable, head, entry int, count ringgadget.Count) frontend.Variable {
	transmitted := slices.Clone(ciphertext[:head+len(count.Active)*entry])
	// An entry at or past the count packs as zero, the chunk the cut falls in then equals pack_left31 of the transmitted bytes.
	for i, active := range count.Active {
		offset := head + i*entry
		copy(transmitted[offset:], masked(api, active, transmitted[offset:offset+entry]))
	}
	fields := shared.PackDisclosure(api, transmitted)
	// SelectCount sets exactly one candidate, its flag falls on the last chunk of that count's bytes and HashPrefix4 ends the chain there.
	ends := shared.Zeros(len(fields))
	length := frontend.Variable(0)
	for k, selected := range count.OneHot {
		byteLen := head + count.Candidate(k)*entry
		last := (byteLen+gadget.HashBytesChunkSize-1)/gadget.HashBytesChunkSize - 1
		ends[last] = api.Add(ends[last], selected)
		length = api.Add(length, api.Mul(selected, byteLen))
	}
	// The tag is the selected count's transmitted length, two counts whose chains agree over trailing zero bytes hash apart.
	return gadget.PoseidonHash(api, []frontend.Variable{length, ringgadget.HashPrefix4(api, fields, ends)})
}

// Opened holds every output slot once, every section reads these wires.
type Opened struct {
	Slots []shared.Output
	// OutputCount is the published m.
	OutputCount frontend.Variable
	Count       ringgadget.Count
	// OutputChain covers every published slot hash, a dummy's included, zero past m as SPP's padded chain reads.
	OutputChain frontend.Variable
	hasData     frontend.Variable
	records     [][]frontend.Variable
	tails       [][]frontend.Variable
}

func OpenSlots(api frontend.API, rc frontend.Rangechecker, w AuditWires, e Envelope, shape StreamShape, layout Layout, outputs []OutputWires, outputCount frontend.Variable) Opened {
	count := ringgadget.SelectCount(api, outputCount, 1, len(outputs))
	opened := Opened{Slots: make([]shared.Output, len(outputs)), OutputCount: outputCount, Count: count, hasData: layout.HasData, records: make([][]frontend.Variable, len(outputs))}
	hashes := make([]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot := output.Output.Open(api)
		active := count.Active[i]
		// An omitted slot holds no note, SPP's padded chain would miss it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: slot.Utxo})
		// The auditor rebuilds every commitment from the sealed key's blinding, another value leaves the slot unopened.
		w.AssertBlinding(api, e, slot, active, i)
		assertNoData(api, layout.HasData, slot)
		opened.records[i] = output.record(api, rc, slot)
		if shape.Data {
			opened.tails = append(opened.tails, dataTail(api, rc, slot))
		}
		opened.Slots[i], hashes[i] = slot, api.Mul(active, slot.Hash)
	}
	opened.OutputChain = gadget.HashChain4(api, hashes)
	return opened
}

// AssertBlinding holds a published dummy's blinding too, an all dummy transfer has no other link to SPP's seed.
func (w AuditWires) AssertBlinding(api frontend.API, e Envelope, slot shared.Output, active frontend.Variable, i int) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: slot.Blinding, B: transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)})
}

// Head opens every audit statement under domain, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs. The stream's ephemeral key is tx_u, txPk already binds it.
func (e Envelope) Head(w AuditWires, s Stream, domain frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{domain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1]},
		s.sealed.Auditor,
		[]frontend.Variable{s.digest, e.salt, w.Layout},
	)
}

// AssertClamped pins the RFC 7748 clamped encoding, the one byte string per X25519 key.
func AssertClamped(api frontend.API, secret [32]frontend.Variable) {
	low := api.ToBinary(secret[0], 8)
	high := api.ToBinary(secret[31], 8)
	// Bits 0 to 2 are clear, the scalar is a multiple of the cofactor.
	for _, bit := range low[:3] {
		api.AssertIsEqual(bit, 0)
	}
	// Bit 254 is set and bit 255 is clear, the top RFC 7748 fixes.
	api.AssertIsEqual(high[6], 1)
	api.AssertIsEqual(high[7], 0)
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}
