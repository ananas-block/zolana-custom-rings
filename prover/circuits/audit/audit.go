// Read after shared/envelope.go, shared/derivation.go, shared/utxo.go. Read
// before audit/layout.go, audit/delivered.go, audit/anonymous.go, transfer/transfer.go.

// Package audit proves what a ring auditor reads from a ring transfer.
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

// AnonymousAuditShape sizes the anonymous section, FullOpenings the entry layout of a spend of default-ring notes.
type AnonymousAuditShape struct {
	InputClass   int
	Outputs      int
	FullOpenings bool
}

func (s AnonymousAuditShape) Ranges() StreamRanges {
	if s.FullOpenings {
		return EntryRanges(s.InputClass, s.Outputs)
	}
	return CommitmentRanges(s.InputClass, s.Outputs)
}

type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingProgramID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingProgramID frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
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
	txPk := shared.PackBounded(api, TaggedPubkey(api, w.TxViewingSk))
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
	EvidenceHead, Entry int
	InputClass, Outputs int
	RecordBlocks        int
}

const (
	streamBlockLen = 16
	// StreamFirstCounter is aes.Cipher.CTREncrypt's first counter, mirrored by STREAM_FIRST_COUNTER.
	StreamFirstCounter = 2
	EnvelopeKeyLen     = 32
	// InputHashLen mirrors INPUT_HASH_LEN.
	InputHashLen = fieldLen
	fieldLen     = 32
	amountLen    = 8
	// EntryEvidenceHeadLen mirrors ENTRY_EVIDENCE_HEAD_LEN.
	EntryEvidenceHeadLen = 2 * fieldLen
	// EntryInputLen mirrors ENTRY_INPUT_LEN.
	EntryInputLen = InputHashLen + amountLen + 2*fieldLen
	// AnonymousRecordLen mirrors ANONYMOUS_RECORD_LEN.
	AnonymousRecordLen = fieldLen + amountLen + 2*fieldLen
	// ExitRecordLen mirrors EXIT_RECORD_LEN.
	ExitRecordLen = 2*fieldLen + amountLen
	// EscrowExitRecordLen mirrors ESCROWED_EXIT_RECORD_LEN.
	EscrowExitRecordLen      = fieldLen + amountLen
	AnonymousRecordBlocks    = (AnonymousRecordLen + streamBlockLen - 1) / streamBlockLen
	ConfidentialRecordBlocks = (ExitRecordLen + streamBlockLen - 1) / streamBlockLen
)

func ConfidentialRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{Entry: InputHashLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: ConfidentialRecordBlocks}
}

func CommitmentRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{Entry: InputHashLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: AnonymousRecordBlocks}
}

func EntryRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{EvidenceHead: EntryEvidenceHeadLen, Entry: EntryInputLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: AnonymousRecordBlocks}
}

func (r StreamRanges) EvidenceLen(count int) int {
	return r.EvidenceHead + count*r.Entry
}

// EnvelopeLen is what the frame carries, with no padding.
func (r StreamRanges) EnvelopeLen(count int) int {
	return EnvelopeKeyLen + r.EvidenceLen(count)
}

// MaxEvidenceBlocks is one value per key, every rail of a key shares one circuit.
func (r StreamRanges) MaxEvidenceBlocks() int {
	return (r.EvidenceLen(r.InputClass) + streamBlockLen - 1) / streamBlockLen
}

func (r StreamRanges) EnvelopeBlocks() int {
	return EnvelopeKeyLen/streamBlockLen + r.MaxEvidenceBlocks()
}

// RecordCounter must match the readers, another counter decrypts noise.
func (r StreamRanges) RecordCounter(i int) int {
	return StreamFirstCounter + r.EnvelopeBlocks() + i*r.RecordBlocks
}

// CapacityBlocks covers every delivered slot's unused record.
func (r StreamRanges) CapacityBlocks() int {
	return r.EnvelopeBlocks() + r.Outputs*r.RecordBlocks
}

func (r StreamRanges) RecordOffset(i int) int {
	return (r.RecordCounter(i) - StreamFirstCounter) * streamBlockLen
}

// Evidence entry i is absent at or past Count.
type Evidence struct {
	Head    []frontend.Variable
	Entries [][]frontend.Variable
	Count   ringgadget.Count
}

type Stream struct {
	ranges StreamRanges
	sealed shared.Sealed
	digest frontend.Variable
}

// SealStream mirrors AuditEnvelope::encode in program-libs/interface/src/proof/audit_stream.rs.
func (w AuditWires) SealStream(api frontend.API, ranges StreamRanges, evidence Evidence, records [][]frontend.Variable) Stream {
	// The envelope's padding ends on the block before R0, the longest evidence never reaches a record's counter.
	plaintext := slices.Concat(w.TxViewingSk[:], evidence.Head, slices.Concat(evidence.Entries...))
	plaintext = append(plaintext, shared.Zeros(ranges.EnvelopeBlocks()*streamBlockLen-len(plaintext))...)
	// Each record fills exactly R blocks, a counter serving two regions reveals the XOR of their plaintexts.
	for _, record := range records {
		plaintext = slices.Concat(plaintext, record, shared.Zeros(ranges.RecordBlocks*streamBlockLen-len(record)))
	}
	// A plaintext off its ranges moves every record off the counters the readers use.
	if len(plaintext) != ranges.CapacityBlocks()*streamBlockLen {
		panic("audit: the stream plaintext differs from its ranges")
	}
	// One key expansion and nonce cover every block, the cipher's tables bound every plaintext and ciphertext byte.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: w.EphSk, AuditorPk: w.AuditorPk, Info: shared.AuditEncInfo}.SealStream(api)
	return Stream{ranges: ranges, sealed: sealed, digest: envelopeDigest(api, ranges, evidence, sealed.Ciphertext)}
}

// envelopeDigest covers the class's envelope bytes alone, a record region and the padding past it reach no digest.
func envelopeDigest(api frontend.API, ranges StreamRanges, evidence Evidence, ciphertext []frontend.Variable) frontend.Variable {
	return countedDigest(api, ciphertext, EnvelopeKeyLen+len(evidence.Head), ranges.Entry, evidence.Count)
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

func (s Stream) record(i int) []frontend.Variable {
	return s.sealed.Ciphertext[s.ranges.RecordOffset(i):s.ranges.RecordOffset(i+1)]
}

// slotBytes hold the one encoding below q, zero off a UTXO.
type slotBytes struct {
	asset, nullifierPk [fieldLen]frontend.Variable
	amount             []frontend.Variable
	blinding           [fieldLen]frontend.Variable
}

// exitRecord mirrors ExitRecord::encode in program-libs/interface/src/proof/audit_stream.rs.
func (b slotBytes) exitRecord() []frontend.Variable {
	return slices.Concat(b.asset[:], b.amount, b.nullifierPk[:])
}

// Opened holds every output slot once, every section reads these wires.
type Opened struct {
	Slots []shared.Output
	// OutputCount is the published m.
	OutputCount frontend.Variable
	Count       ringgadget.Count
	// OutputChain covers every published slot hash, a dummy's included, zero past m as SPP's padded chain reads.
	OutputChain frontend.Variable
	ExitsBitmap frontend.Variable
	bytes       []slotBytes
}

type outputWires interface {
	utxoWires() shared.UtxoWires
}

func OpenSlots[O outputWires](api frontend.API, rc frontend.Rangechecker, w AuditWires, e Envelope, outputs []O, outputCount frontend.Variable) Opened {
	count := ringgadget.SelectCount(api, outputCount, 1, len(outputs))
	opened := Opened{Slots: make([]shared.Output, len(outputs)), OutputCount: outputCount, Count: count, bytes: make([]slotBytes, len(outputs))}
	hashes := make([]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot := OpenOutput(api, output.utxoWires())
		active := count.Active[i]
		// An omitted slot holds no note, SPP's padded chain would miss it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: slot.Utxo})
		// The auditor rebuilds every commitment from the sealed key's blinding with no ring data, another value leaves the slot unopened.
		w.AssertBlinding(api, e, slot, active, i)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.RingDataHash})
		// FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
		opened.bytes[i] = slotBytes{
			asset:       ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Asset)),
			nullifierPk: ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.NullifierPk)),
			amount:      ringgadget.UintBytesBE(api, api.Mul(slot.Utxo, slot.Amount), amountLen),
			blinding:    ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Blinding)),
		}
		opened.Slots[i], hashes[i] = slot, api.Mul(active, slot.Hash)
	}
	opened.OutputChain = gadget.HashChain4(api, hashes)
	// The program cuts every ciphertext length from the same positions.
	exits := make([]frontend.Variable, len(opened.Slots))
	for i, slot := range opened.Slots {
		exits[i] = slot.Exit
	}
	opened.ExitsBitmap = weightedBits(api, exits)
	return opened
}

// weightedBits mirrors exits_bitmap in program-libs/interface/src/instructions/transact.rs.
func weightedBits(api frontend.API, bits []frontend.Variable) frontend.Variable {
	bitmap := frontend.Variable(0)
	for i, bit := range bits {
		bitmap = api.Add(bitmap, api.Mul(bit, uint64(1)<<i))
	}
	return bitmap
}

// OpenOutput opens an output slot the auditor reads, no UTXO carries a data hash the recipient never learns.
func OpenOutput(api frontend.API, o shared.UtxoWires) shared.Output {
	opened := o.Open(api)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: o.DataHash})
	return opened
}

func assertOwnerKey(api frontend.API, slot shared.Output, key [32]frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: slot.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, key)})
}

// AssertBlinding holds a published dummy's blinding too, an all dummy transfer has no other link to SPP's seed.
func (w AuditWires) AssertBlinding(api frontend.API, e Envelope, slot shared.Output, active frontend.Variable, i int) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: slot.Blinding, B: transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)})
}

// Head opens every audit statement under domain, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs.
func (e Envelope) Head(w AuditWires, s Stream, domain frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{domain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1]},
		s.sealed.Auditor, s.sealed.Eph,
		[]frontend.Variable{s.digest, e.salt, w.Layout},
	)
}

// InputEvidence transmits be32(hash_i) per slot, the list private_tx_hash chains.
func InputEvidence(api frontend.API, rc frontend.Rangechecker, hashes []frontend.Variable, count ringgadget.Count) Evidence {
	entries := make([][]frontend.Variable, len(hashes))
	for i, hash := range hashes {
		// The be32 below q is one encoding, hash + q would name no note.
		bytes := ringgadget.FieldToBytesBEWith(api, rc, hash)
		entries[i] = bytes[:]
	}
	return Evidence{Entries: entries, Count: count}
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

// TaggedPubkey is 0x04 ‖ u of the clamped secret, the generator gadget bounds every secret byte.
func TaggedPubkey(api frontend.API, secret [32]frontend.Variable) []frontend.Variable {
	return shared.Tagged(x25519.ScalarMulGenerator(api, secret))
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}
