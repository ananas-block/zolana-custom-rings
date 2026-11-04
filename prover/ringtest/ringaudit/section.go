package ringaudit

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// SectionCircuit proves the audit section alone, no key proves it.
type SectionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Shape           audit.StreamShape `gnark:"-"`
	audit.AuditWires
	OutputCount frontend.Variable
	Outputs     []audit.OutputWires
	InputCount  frontend.Variable
	Inputs      []shared.UtxoWires
	Entries     []audit.EntryWires
}

func NewSectionCircuit(shape audit.StreamShape) *SectionCircuit {
	c := &SectionCircuit{Shape: shape, Outputs: make([]audit.OutputWires, shape.Outputs), Inputs: make([]shared.UtxoWires, shape.InputClass)}
	if shape.Entry {
		c.Entries = make([]audit.EntryWires, shape.InputClass)
	}
	return c
}

func (c *SectionCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	envelope := c.OpenEnvelope(api, rc)
	layout := c.Shape.DecodeLayout(api, c.Layout)
	opened := audit.OpenSlots(api, rc, c.AuditWires, envelope, c.Shape, layout, c.Outputs, c.OutputCount)
	count := ringgadget.SelectCount(api, c.InputCount, 1, len(c.Inputs))
	slots := make([]shared.Output, len(c.Inputs))
	for i, input := range c.Inputs {
		slots[i] = input.OpenInput(api)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, count.Active[i]), V: slots[i].Utxo})
	}
	stream := c.SealStream(api, rc, c.Shape, opened, audit.SpentInputs{Slots: slots, Count: count, Entries: c.Entries})
	statement := append(envelope.Head(c.AuditWires, stream, shared.AuditStatementDomain),
		stream.NoSpend, c.OutputCount, opened.OutputChain, stream.RecordChain, stream.TailChain, c.InputCount)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// Slot is one note and the preimages its plaintext names, the host twin of audit.OutputWires and audit.EntryWires.
type Slot struct {
	Utxo     Utxo
	OwnerKey [32]byte
	Mint     [32]byte
}

// Section is one audited transfer's slots.
type Section struct {
	Transfer
	Shape   audit.StreamShape
	HasData bool
	// Outputs holds N slots, the last Omitted of them past the published m.
	Outputs    []Slot
	Omitted    int
	InputCount int
	Inputs     []Slot
}

// RingOwnerKey and ExitOwnerKey own the fixture outputs, PayerKey the fixture ring inputs and DefaultOwnerKey the fixture default-ring inputs.
var (
	RingOwnerKey    = ringtest.Repeat(0xb2)
	ExitOwnerKey    = ringtest.Repeat(0xe5)
	PayerKey        = ringtest.Repeat(0xa1)
	DefaultOwnerKey = ringtest.Repeat(0xa2)
)

// EnrolledNullifierPk is the fixture ring key.
func EnrolledNullifierPk(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, big.NewInt(21))
}

// ZeroKey is Poseidon(0), the key of a note with no secret.
func ZeroKey(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustNullifierPk(t, big.NewInt(0))
}

// NewSection lays out an enrolled ring note in slot 0, a zero-key ring note in slot 1 of a wider key, an exit next and dummies after, spending one ring note and on an entry key one default-ring note.
func NewSection(t testing.TB, shape audit.StreamShape) Section {
	t.Helper()
	s := Section{Transfer: NewTransfer(t), Shape: shape, InputCount: 1, Outputs: make([]Slot, shape.Outputs), Inputs: make([]Slot, shape.InputClass)}
	for i := range s.Outputs {
		s.Outputs[i] = s.Dummy(t, i)
	}
	s.Outputs[0] = s.RingOutput(t, 0, RingOwnerKey, EnrolledNullifierPk(t), 100)
	switch {
	case shape.Outputs >= 4:
		s.Outputs[1] = s.RingOutput(t, 1, RingOwnerKey, ZeroKey(t), 30)
		s.Outputs[2] = s.Exit(t, 2)
	case shape.Outputs >= 2:
		s.Outputs[1] = s.Exit(t, 1)
	}
	for i := range s.Inputs {
		s.Inputs[i] = Slot{Utxo: SpareInput(i)}
	}
	s.Inputs[0] = Slot{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), s.RingProgramID, 100, 51), OwnerKey: PayerKey, Mint: FixtureMint}
	if shape.Entry {
		s.InputCount = 2
		s.Inputs[1] = Slot{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, DefaultOwnerKey), spptest.MustNullifierPk(t, big.NewInt(8)), big.NewInt(0), 70, 52), OwnerKey: DefaultOwnerKey, Mint: FixtureMint}
	}
	return s
}

// RingOutput is a data-free ring note of owner under the TXOB blinding of slot i.
func (s Section) RingOutput(t testing.TB, i int, owner [32]byte, nullifierPk *big.Int, amount uint64) Slot {
	t.Helper()
	return Slot{OwnerKey: owner, Mint: FixtureMint, Utxo: Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, owner), NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, FixtureMint), Amount: amount, Blinding: s.Blinding(t, i),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: s.RingProgramID,
	}}
}

// Exit is a data-free default-ring note of slot i.
func (s Section) Exit(t testing.TB, i int) Slot {
	t.Helper()
	slot := s.RingOutput(t, i, ExitOwnerKey, spptest.MustNullifierPk(t, big.NewInt(23)), 40)
	slot.Utxo.RingProgramID = big.NewInt(0)
	return slot
}

// Dummy is a published dummy of slot i, its preimages left zero.
func (s Section) Dummy(t testing.TB, i int) Slot {
	t.Helper()
	return Slot{Utxo: Dummy(OutputTreeID, s.Blinding(t, i))}
}

// Omit cuts the last n slots past the published count, each published slot keeps its index.
func (s Section) Omit(n int) Section {
	s.Outputs = slices.Clone(s.Outputs)
	for i := len(s.Outputs) - n; i < len(s.Outputs); i++ {
		s.Outputs[i] = Slot{Utxo: unpublished()}
	}
	s.Omitted = n
	return s
}

// Spending replaces the inputs with n live ring notes of the payer.
func (s Section) Spending(t testing.TB, n int) Section {
	t.Helper()
	s.Inputs = slices.Clone(s.Inputs)
	for i := range s.Inputs {
		s.Inputs[i] = Slot{Utxo: SpareInput(i)}
		if i < n {
			s.Inputs[i] = Slot{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), s.RingProgramID, 10, 60+int64(i)), OwnerKey: PayerKey, Mint: FixtureMint}
		}
	}
	return s
}

func (s Section) OutputCount() int {
	return len(s.Outputs) - s.Omitted
}

func (s Section) Layout() Layout {
	return Layout{HasData: s.HasData, Entry: s.Shape.Entry}
}

// RealInputs mirrors the sealed R.
func (s Section) RealInputs() int {
	real := 0
	for _, input := range s.Inputs {
		if input.Utxo.isUtxo() {
			real++
		}
	}
	return real
}

// DefaultBits mirrors the sealed default bits.
func (s Section) DefaultBits() uint64 {
	bits := uint64(0)
	for i, input := range s.Inputs {
		if input.Utxo.isExit() {
			bits |= 1 << i
		}
	}
	return bits
}

// EnvelopePlaintext mirrors AuditEnvelope::encode.
func (s Section) EnvelopePlaintext(t testing.TB) []byte {
	t.Helper()
	plaintext := slices.Concat(s.Keys.txViewingSk[:], []byte{byte(s.RealInputs())})
	if !s.Shape.Entry {
		return plaintext
	}
	plaintext = binary.BigEndian.AppendUint64(plaintext, s.DefaultBits())
	for _, input := range s.Inputs {
		plaintext = append(plaintext, input.entry(t)...)
	}
	return plaintext
}

// entry mirrors EntryInput::encode, zero off a default-ring note.
func (slot Slot) entry(t testing.TB) []byte {
	t.Helper()
	if !slot.Utxo.isExit() {
		return make([]byte, audit.EntryInputLen)
	}
	u := slot.Utxo
	nullifierPk, blinding := spptest.MustFieldBytes(t, u.NullifierPk), spptest.MustFieldBytes(t, u.Blinding)
	dataHash, ringDataHash := spptest.MustFieldBytes(t, u.DataHash), spptest.MustFieldBytes(t, u.RingDataHash)
	return slices.Concat(slot.OwnerKey[:], nullifierPk[:], binary.BigEndian.AppendUint64(nil, u.Amount), slot.Mint[:], blinding[:], dataHash[:], ringDataHash[:])
}

// Record mirrors AuditRecord::encode, zero on a dummy.
func (slot Slot) Record(t testing.TB) []byte {
	t.Helper()
	record := make([]byte, audit.RecordLen)
	if !slot.Utxo.isUtxo() {
		return record
	}
	record[0] = audit.KindRing
	if slot.Utxo.isExit() {
		record[0] = audit.KindExit
	}
	binary.BigEndian.PutUint64(record[8:16], slot.Utxo.Amount)
	copy(record[16:48], slot.OwnerKey[:])
	copy(record[48:80], slot.Mint[:])
	nullifierPk := spptest.MustFieldBytes(t, slot.Utxo.NullifierPk)
	copy(record[80:], nullifierPk[:])
	return record
}

// Tail mirrors DataTail::encode, zero on a dummy.
func (slot Slot) Tail(t testing.TB) []byte {
	t.Helper()
	if !slot.Utxo.isUtxo() {
		return make([]byte, audit.TailLen)
	}
	dataHash, ringDataHash := spptest.MustFieldBytes(t, slot.Utxo.DataHash), spptest.MustFieldBytes(t, slot.Utxo.RingDataHash)
	return slices.Concat(dataHash[:], ringDataHash[:])
}

// Plaintexts are the sealed regions of a section, a test edits them to claim what the circuit refuses.
type Plaintexts struct {
	Envelope []byte
	Records  [][]byte
	Tails    [][]byte
}

func (s Section) Plaintexts(t testing.TB) Plaintexts {
	t.Helper()
	p := Plaintexts{Envelope: s.EnvelopePlaintext(t), Records: make([][]byte, len(s.Outputs))}
	for i, output := range s.Outputs {
		p.Records[i] = output.Record(t)
		if s.Shape.Data {
			p.Tails = append(p.Tails, output.Tail(t))
		}
	}
	return p
}

// Seal runs the key's cipher over plaintexts, every region at its counters.
func (s Section) Seal(t testing.TB, p Plaintexts) Stream {
	t.Helper()
	return s.Keys.SealAuditorStream(t, s.Shape.Ranges(), p.Envelope, p.Records, p.Tails)
}

func (s Section) Stream(t testing.TB) Stream {
	t.Helper()
	return s.Seal(t, s.Plaintexts(t))
}

// PublishedRecords are the record ciphertexts the frame carries.
func (s Section) PublishedRecords(stream Stream) [][]byte {
	records := make([][]byte, s.OutputCount())
	for i := range records {
		records[i] = stream.Record(i)
	}
	return records
}

// PublishedTails are the tail ciphertexts the frame carries, none while has_data is clear.
func (s Section) PublishedTails(stream Stream) [][]byte {
	if !s.HasData {
		return nil
	}
	tails := make([][]byte, s.OutputCount())
	for i := range tails {
		tails[i] = stream.Tail(i)
	}
	return tails
}

// PublishedHashes are the output hashes SPP publishes.
func (s Section) PublishedHashes(t testing.TB) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, s.OutputCount())
	for i := range hashes {
		hashes[i] = s.Outputs[i].Utxo.Hash(t)
	}
	return hashes
}

// Claim is the part of the statement the program reads off the frame, a test moves one cell.
type Claim struct {
	NoSpend     bool
	OutputCount int
	InputCount  int
}

func (s Section) Claim() Claim {
	return Claim{NoSpend: s.RealInputs() == 0, OutputCount: s.OutputCount(), InputCount: s.InputCount}
}

// StatementOf is what the program would hash over stream under claim.
func (s Section) StatementOf(t testing.TB, stream Stream, claim Claim) []*big.Int {
	t.Helper()
	tailChain := big.NewInt(0)
	if tails := s.PublishedTails(stream); tails != nil {
		tailChain = RegionChain(t, tails, len(s.Outputs))
	}
	head := s.AuditHead(t, s.Layout(), stream.Envelope(claim.InputCount))
	return append(head.Elements(t), big.NewInt(ringtest.Bit(claim.NoSpend)), big.NewInt(int64(claim.OutputCount)),
		OutputChain(t, s.PublishedHashes(t), len(s.Outputs)), RegionChain(t, s.PublishedRecords(stream), len(s.Outputs)),
		tailChain, big.NewInt(int64(claim.InputCount)))
}

func (s Section) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return s.StatementOf(t, s.Stream(t), s.Claim())
}

// Wires open a slot, a slot with no mint opens the zero chunks.
func (slot Slot) Wires() audit.OutputWires {
	w := audit.OutputWires{Output: slot.Utxo.Wires()}
	ringtest.SetBytes(w.OwnerKey[:], slot.OwnerKey[:])
	chunks := protocol.MintChunks(slot.Mint)
	w.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	return w
}

func (slot Slot) entryWires() audit.EntryWires {
	w := audit.EntryWires{}
	ringtest.SetBytes(w.OwnerKey[:], slot.OwnerKey[:])
	chunks := protocol.MintChunks(slot.Mint)
	w.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	return w
}

// Circuit assigns the section honestly under its own statement.
func (s Section) Circuit(t testing.TB) *SectionCircuit {
	t.Helper()
	c := NewSectionCircuit(s.Shape)
	c.PublicInputHash = spptest.MustHashChain4(t, s.Statement(t))
	c.AuditWires = s.Wires(s.Layout())
	c.OutputCount = s.OutputCount()
	c.InputCount = s.InputCount
	for i, output := range s.Outputs {
		c.Outputs[i] = output.Wires()
	}
	for i, input := range s.Inputs {
		c.Inputs[i] = input.Utxo.Wires()
		if s.Shape.Entry {
			c.Entries[i] = input.entryWires()
		}
	}
	return c
}

// Note is what a reader rebuilt, its Hash the published commitment it matched.
type Note struct {
	Kind        byte
	OwnerKey    [32]byte
	Mint        [32]byte
	Amount      uint64
	NullifierPk *big.Int
	Blinding    *big.Int
	Hash        *big.Int
}

// AuditReader rebuilds a slot from the stream and the frame, holding no mint registry and no other slot.
type AuditReader struct {
	Transfer
	Shape      audit.StreamShape
	HasData    bool
	InputCount int
	TreeID     uint16
}

func (s Section) Reader() AuditReader {
	return AuditReader{Transfer: s.Transfer, Shape: s.Shape, HasData: s.HasData, InputCount: s.InputCount, TreeID: OutputTreeID}
}

// Envelope reads R and the default bits.
func (r AuditReader) Envelope(t testing.TB, stream Stream) (realInputs int, defaultBits uint64) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	realInputs = int(plaintext[audit.EnvelopeKeyLen])
	if r.Shape.Entry {
		defaultBits = binary.BigEndian.Uint64(plaintext[audit.EnvelopeKeyLen+audit.RealInputCountLen:])
	}
	return realInputs, defaultBits
}

// Read rebuilds slot i and accepts only an exact match, nil on a dummy.
func (r AuditReader) Read(t testing.TB, stream Stream, i int, published *big.Int) (*Note, error) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	offset := stream.Ranges.RecordOffset(i)
	record := plaintext[offset : offset+audit.RecordLen]
	kind := record[0]
	if kind == audit.KindDummy {
		if slices.ContainsFunc(record, func(b byte) bool { return b != 0 }) {
			return nil, fmt.Errorf("slot %d: a dummy carries a value", i)
		}
		return nil, nil
	}
	if kind != audit.KindRing && kind != audit.KindExit || slices.ContainsFunc(record[1:8], func(b byte) bool { return b != 0 }) {
		return nil, fmt.Errorf("slot %d: not a record", i)
	}
	dataHash, ringDataHash := big.NewInt(0), big.NewInt(0)
	if r.HasData {
		tailOffset := stream.Ranges.TailOffset(i)
		tail := plaintext[tailOffset : tailOffset+audit.TailLen]
		dataHash, ringDataHash = new(big.Int).SetBytes(tail[:32]), new(big.Int).SetBytes(tail[32:])
	}
	// The sealed key alone fixes the blinding, no fixture value reaches the reader.
	seedOut, err := protocol.OutputBlindingSeed(r.FirstNullifier, ringprotocol.BlindingSeed(t, [32]byte(plaintext[:audit.EnvelopeKeyLen]), r.Salt))
	blinding := ringprotocol.OutputBlinding(t, r.FirstNullifier, spptest.MustHash(t, seedOut, err), i)
	note := Note{Kind: kind, OwnerKey: [32]byte(record[16:48]), Mint: [32]byte(record[48:80]), Amount: binary.BigEndian.Uint64(record[8:16]), NullifierPk: new(big.Int).SetBytes(record[80:]), Blinding: blinding}
	ringID := big.NewInt(0)
	if kind == audit.KindRing {
		ringID = r.RingProgramID
	}
	note.Hash = Utxo{
		Domain: protocol.UtxoDomain, TreeID: r.TreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, note.OwnerKey), NullifierPk: note.NullifierPk,
		Asset: ringtest.AssetField(t, note.Mint), Amount: note.Amount, Blinding: note.Blinding,
		DataHash: dataHash, RingDataHash: ringDataHash, RingProgramID: ringID,
	}.Hash(t)
	if note.Hash.Cmp(published) != 0 {
		return nil, fmt.Errorf("slot %d: the record rebuilds no published commitment", i)
	}
	return &note, nil
}
