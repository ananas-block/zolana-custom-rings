// Holds the one auditor stream every transfer proof seals and the slot opening
// every section reads. A counter serving two regions reveals the XOR of their
// plaintexts, a digest over another length lets a frame cut what the auditor opens.
//
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

// Local constraints, SealStream and OpenSlots assert them:
// 1. One key expansion and one nonce cover the capacity sized plaintext, aes.Cipher.CTREncrypt gives each 16-byte block its own counter from 2.
// 2. The envelope region holds tx_viewing_sk then the evidence, slot i's record starts at R0 + i * R, every region zero padded to whole blocks, no counter serves two regions.
// 3. digest(envelope_ct) covers exactly the EnvelopeLen bytes input_count selects, an entry at or past the count packs as zero.
// 4. exits_bitmap has bit i set exactly when slot i is a UTXO of the default ring, the layout holds no exit flag.
//
// Program-derived facts, the statement fixes them:
// 5. input_count is the frame's nullifier count and exits_bitmap the frame's exit positions, the program cuts every ciphertext length from both and the layout.
// 6. AuditorPk is the ring account's auditor key, the salt the instruction's.
//
// Guarantees the section leans on:
// 7. The Rust and TS SDKs draw a fresh eph_sk and salt per build, the proof holds no freshness and a repeat reuses key and nonce over another plaintext.
// 8. AssertRingMemberOrFree in spp_transaction/shared/ring.go holds every UTXO's ring id to 0 or the ring's, so Exit names a note of the default ring.

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

// OpenEnvelope binds tx_viewing_sk to its tagged public key and the output blinding seed.
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

// StreamRanges sizes one key's auditor stream in AES blocks, mirrored by AuditStreamLayout in program-libs/interface/src/proof/audit_stream.rs.
type StreamRanges struct {
	// EvidenceHead is the bytes every published count carries, FirstEntry and Entry the bytes of input 0 and of every later input.
	EvidenceHead, FirstEntry, Entry int
	InputClass, Outputs             int
	RecordBlocks                    int
}

const (
	streamBlockLen = 16
	// StreamFirstCounter is the first block counter of aes.Cipher.CTREncrypt, mirrored by STREAM_FIRST_COUNTER.
	StreamFirstCounter = 2
	// EnvelopeKeyLen is the sealed tx_viewing_sk, two blocks every envelope opens with.
	EnvelopeKeyLen = 32
	// InputPrefixLen is prefix16, the first bytes of a spent hash's be32, mirrored by INPUT_PREFIX_BYTES.
	InputPrefixLen = 16
	fieldLen       = 32
	amountLen      = 8
	// EntryEvidenceHeadLen is sender_key and be32(sender_nullifier_pk), mirrored by ENTRY_EVIDENCE_HEAD_LEN.
	EntryEvidenceHeadLen = 2 * fieldLen
	// EntryInputLen is one entry input, mirrored by ENTRY_INPUT_LEN.
	EntryInputLen = amountLen + 2*fieldLen
	// AnonymousRecordLen is an anonymous ring output's or hidden dummy's record, mirrored by ANONYMOUS_RECORD_LEN.
	AnonymousRecordLen = fieldLen + amountLen + 2*fieldLen
	// ExitRecordLen is an exit's record, mirrored by EXIT_RECORD_LEN.
	ExitRecordLen = 2*fieldLen + amountLen
	// EscrowExitRecordLen is an exit's record under key escrow, mirrored by ESCROWED_EXIT_RECORD_LEN.
	EscrowExitRecordLen = fieldLen + amountLen
	// AnonymousRecordBlocks is R of the anonymous family, it holds the longest anonymous record.
	AnonymousRecordBlocks = (AnonymousRecordLen + streamBlockLen - 1) / streamBlockLen
	// ConfidentialRecordBlocks is R of the confidential family, it holds the longest exit record.
	ConfidentialRecordBlocks = (ExitRecordLen + streamBlockLen - 1) / streamBlockLen
)

// ConfidentialRanges has prefix16(input_hash_i) entries, a signer rail transmits none of them.
func ConfidentialRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{FirstEntry: InputPrefixLen, Entry: InputPrefixLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: ConfidentialRecordBlocks}
}

// CommitmentRanges has be32(input_hash_0) then prefix16(input_hash_i) entries.
func CommitmentRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{FirstEntry: fieldLen, Entry: InputPrefixLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: AnonymousRecordBlocks}
}

// EntryRanges has the sender head then one opening per input.
func EntryRanges(inputClass, outputs int) StreamRanges {
	return StreamRanges{EvidenceHead: EntryEvidenceHeadLen, FirstEntry: EntryInputLen, Entry: EntryInputLen, InputClass: inputClass, Outputs: outputs, RecordBlocks: AnonymousRecordBlocks}
}

// EvidenceLen is head + first + (count - 1) * entry, zero on the signer rail's count of zero.
func (r StreamRanges) EvidenceLen(count int) int {
	if count == 0 {
		return 0
	}
	return r.EvidenceHead + r.FirstEntry + (count-1)*r.Entry
}

// EnvelopeLen is the transmitted envelope, the frame carries these bytes and no padding.
func (r StreamRanges) EnvelopeLen(count int) int {
	return EnvelopeKeyLen + r.EvidenceLen(count)
}

// MaxEvidenceBlocks is E_max, ceil(EvidenceLen(class) / 16), the same on every rail of a key since one circuit serves them.
func (r StreamRanges) MaxEvidenceBlocks() int {
	return (r.EvidenceLen(r.InputClass) + streamBlockLen - 1) / streamBlockLen
}

// EnvelopeBlocks is 2 + E_max, the region's maximum at any count.
func (r StreamRanges) EnvelopeBlocks() int {
	return EnvelopeKeyLen/streamBlockLen + r.MaxEvidenceBlocks()
}

// RecordCounter is R0 + i * R, R0 = 2 + 2 + E_max, a reader on another counter decrypts noise.
func (r StreamRanges) RecordCounter(i int) int {
	return StreamFirstCounter + r.EnvelopeBlocks() + i*r.RecordBlocks
}

// CapacityBlocks is what the one CTREncrypt covers, every delivered slot's unused record included.
func (r StreamRanges) CapacityBlocks() int {
	return r.EnvelopeBlocks() + r.Outputs*r.RecordBlocks
}

func (r StreamRanges) RecordOffset(i int) int {
	return (r.RecordCounter(i) - StreamFirstCounter) * streamBlockLen
}

// Evidence is what the envelope opens of the inputs, entry i absent at or past Count.
type Evidence struct {
	Head    []frontend.Variable
	Entries [][]frontend.Variable
	Count   ringgadget.Count
}

// Stream is one transfer's sealed auditor stream, read through record and the statement head alone.
type Stream struct {
	ranges StreamRanges
	sealed shared.Sealed
	digest frontend.Variable
}

// SealStream encrypts the region padded plaintext once under CRING/adt1, mirrored by AuditEnvelope::encode in program-libs/interface/src/proof/audit_stream.rs.
//
//	tx_viewing_sk ‖ evidence head ‖ entry per input slot ‖ zero pad to 2 + E_max blocks ‖ (record ‖ zero pad to R blocks) per slot
func (w AuditWires) SealStream(api frontend.API, ranges StreamRanges, evidence Evidence, records [][]frontend.Variable) Stream {
	// 1. The envelope's padding ends on the block before R0, the longest evidence never reaches a record's counter.
	plaintext := slices.Concat(w.TxViewingSk[:], evidence.Head, slices.Concat(evidence.Entries...))
	plaintext = append(plaintext, shared.Zeros(ranges.EnvelopeBlocks()*streamBlockLen-len(plaintext))...)
	// 2. Each record fills exactly R blocks, slot i's first byte encrypts under counter R0 + i * R and no counter serves two regions.
	for _, record := range records {
		plaintext = slices.Concat(plaintext, record, shared.Zeros(ranges.RecordBlocks*streamBlockLen-len(record)))
	}
	// 3. A plaintext off its ranges moves every record off the counters the readers use.
	if len(plaintext) != ranges.CapacityBlocks()*streamBlockLen {
		panic("audit: the stream plaintext differs from its ranges")
	}
	// 4. One key expansion and nonce cover every block, the spread tables of aes.Cipher.CTREncrypt bound every plaintext and ciphertext byte.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: w.EphSk, AuditorPk: w.AuditorPk, Info: shared.AuditEncInfo}.SealStream(api)
	return Stream{ranges: ranges, sealed: sealed, digest: envelopeDigest(api, ranges, evidence, sealed.Ciphertext)}
}

// envelopeDigest is Poseidon(u32 len, HashChain4(pack_left31(envelope_ct))) at the selected count, mirrored by ciphertext_digest in program-libs/interface/src/proof/statement.rs.
func envelopeDigest(api frontend.API, ranges StreamRanges, evidence Evidence, ciphertext []frontend.Variable) frontend.Variable {
	// 1. Only the class's envelope bytes enter, a record region and the padding past it reach no digest.
	transmitted := slices.Clone(ciphertext[:ranges.EnvelopeLen(ranges.InputClass)])
	// 2. An entry at or past the count packs as zero through Count.Active, the chunk the cut falls in then equals pack_left31 of the transmitted bytes.
	offset := EnvelopeKeyLen + len(evidence.Head)
	for i, entry := range evidence.Entries {
		copy(transmitted[offset:], masked(api, evidence.Count.Active[i], transmitted[offset:offset+len(entry)]))
		offset += len(entry)
	}
	fields := shared.PackDisclosure(api, transmitted)
	// 3. SelectCount sets exactly one candidate, its flag falls on the last chunk of that count's envelope and HashPrefix4 ends the chain there.
	ends := shared.Zeros(len(fields))
	length := frontend.Variable(0)
	for k, selected := range evidence.Count.OneHot {
		envelopeLen := ranges.EnvelopeLen(evidence.Count.Candidate(k))
		last := (envelopeLen+gadget.HashBytesChunkSize-1)/gadget.HashBytesChunkSize - 1
		ends[last] = api.Add(ends[last], selected)
		length = api.Add(length, api.Mul(selected, envelopeLen))
	}
	// 4. The tag is the selected count's transmitted length, two counts whose chains agree over trailing zero bytes hash apart.
	return gadget.PoseidonHash(api, []frontend.Variable{length, ringgadget.HashPrefix4(api, fields, ends)})
}

// record is slot i's whole region, each caller cuts the length its slot kind fixes.
func (s Stream) record(i int) []frontend.Variable {
	return s.sealed.Ciphertext[s.ranges.RecordOffset(i):s.ranges.RecordOffset(i+1)]
}

// slotBytes hold one slot's opening in the one encoding below q, zero off a UTXO.
type slotBytes struct {
	asset, nullifierPk [fieldLen]frontend.Variable
	amount             []frontend.Variable
	// blinding is read by a delivered body alone, the auditor derives an anonymous slot's.
	blinding [fieldLen]frontend.Variable
}

// exitRecord is an exit's plaintext, mirrored by ExitRecord::encode in program-libs/interface/src/proof/audit_stream.rs.
//
//	be32(asset) ‖ u64be(amount) ‖ be32(nullifier_pk)
func (b slotBytes) exitRecord() []frontend.Variable {
	return slices.Concat(b.asset[:], b.amount, b.nullifierPk[:])
}

// Opened holds every output slot once, every section reads these wires.
type Opened struct {
	Slots []shared.Output
	// OutputChain is HashChain4 over every slot hash, a dummy's included.
	OutputChain frontend.Variable
	// ExitsBitmap has bit i set exactly when slot i exits.
	ExitsBitmap frontend.Variable
	bytes       []slotBytes
}

type outputWires interface {
	utxoWires() shared.UtxoWires
	carriesBlinding() bool
}

func OpenSlots[O outputWires](api frontend.API, rc frontend.Rangechecker, w AuditWires, e Envelope, outputs []O) Opened {
	opened := Opened{Slots: make([]shared.Output, len(outputs)), bytes: make([]slotBytes, len(outputs))}
	hashes := make([]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot := OpenOutput(api, output.utxoWires())
		// 1. The auditor rebuilds every UTXO's blinding from tx_viewing_sk, no UTXO carries ring data.
		w.AssertBlinding(api, e, slot, i)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.RingDataHash})
		// 2. FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
		opened.bytes[i] = slotBytes{
			asset:       ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Asset)),
			nullifierPk: ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.NullifierPk)),
			amount:      ringgadget.UintBytesBE(api, api.Mul(slot.Utxo, slot.Amount), amountLen),
		}
		if output.carriesBlinding() {
			opened.bytes[i].blinding = ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Blinding))
		}
		opened.Slots[i], hashes[i] = slot, slot.Hash
	}
	opened.OutputChain = gadget.HashChain4(api, hashes)
	// 3. The bitmap follows the opened slots, the program cuts every ciphertext length from the same positions.
	opened.ExitsBitmap = exitsBitmap(api, opened.Slots)
	return opened
}

// exitsBitmap is the sum of Exit * 2^i, mirrored by exits_bitmap in program-libs/interface/src/instructions/transact.rs.
func exitsBitmap(api frontend.API, slots []shared.Output) frontend.Variable {
	bitmap := frontend.Variable(0)
	for i, slot := range slots {
		bitmap = api.Add(bitmap, api.Mul(slot.Exit, uint64(1)<<i))
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

// AssertBlinding pins a live UTXO's blinding to SPP's TXOB blinding over the seed tx_viewing_sk fixes.
func (w AuditWires) AssertBlinding(api frontend.API, e Envelope, slot shared.Output, i int) {
	blinding := transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.Blinding, B: blinding})
}

// Head opens every audit statement under domain, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs.
//
//	domain, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, digest(envelope_ct), salt, layout
func (e Envelope) Head(w AuditWires, s Stream, domain frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{domain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1]},
		s.sealed.Auditor, s.sealed.Eph,
		[]frontend.Variable{s.digest, e.salt, w.Layout},
	)
}

// SpentBySender opens every input slot once, holds it to the sender while live, slot 0 to a UTXO while required, spent UTXO k to nullifier k, and returns utxo * hash per slot.
func SpentBySender(api frontend.API, inputs []shared.UtxoWires, live []frontend.Variable, required, sender frontend.Variable) []frontend.Variable {
	hashes := make([]frontend.Variable, len(inputs))
	previousUtxo := frontend.Variable(1)
	for i, input := range inputs {
		slot := input.Open(api)
		hashes[i] = spentBySender(api, slot, live[i], required, sender, i)
		assertFollowsUtxo(api, slot.Utxo, previousUtxo, i)
		previousUtxo = slot.Utxo
	}
	return hashes
}

// assertFollowsUtxo holds a UTXO behind a UTXO as AssertDummiesLast holds SPP's slots, so spent UTXO k owns nullifier k.
func assertFollowsUtxo(api frontend.API, utxo, previousUtxo frontend.Variable, i int) {
	if i > 0 {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: utxo, V: api.Sub(1, previousUtxo)})
	}
}

// InputPrefixEvidence is prefix16(input_hash_i) per slot under count, a count of zero transmits no entry.
func InputPrefixEvidence(api frontend.API, rc frontend.Rangechecker, hashes []frontend.Variable, count ringgadget.Count) Evidence {
	entries := make([][]frontend.Variable, len(hashes))
	for i, hash := range hashes {
		entries[i] = inputPrefix(api, rc, hash)
	}
	return Evidence{Entries: entries, Count: count}
}

// inputPrefix is prefix16 of the be32 FieldToBytesBEWith holds below q, the prefix of hash + q would name another note.
func inputPrefix(api frontend.API, rc frontend.Rangechecker, hash frontend.Variable) []frontend.Variable {
	bytes := ringgadget.FieldToBytesBEWith(api, rc, hash)
	return bytes[:InputPrefixLen]
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
