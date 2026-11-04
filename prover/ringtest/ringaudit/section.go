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

// RingOwnerKey owns the fixture ring outputs, PayerKey the fixture ring inputs and DefaultOwnerKey the fixture default-ring inputs.
var (
	RingOwnerKey    = ringtest.Repeat(0xb2)
	PayerKey        = ringtest.Repeat(0xa1)
	DefaultOwnerKey = ringtest.Repeat(0xa2)
	FixtureMint     = ringtest.Repeat(0x0a)
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
func NewSection(t testing.TB, shape audit.StreamShape) Audit {
	t.Helper()
	s := NewAudit(t, shape).AllDummies(t)
	s.InputCount = 1
	s.Outputs[0] = s.RingNote(t, 0, RingOwnerKey, EnrolledNullifierPk(t), 100)
	switch {
	case shape.Outputs >= 4:
		s.Outputs[1] = s.RingNote(t, 1, RingOwnerKey, ZeroKey(t), 30)
		s.Outputs[2] = s.NewExit(t, 2)
	case shape.Outputs >= 2:
		s.Outputs[1] = s.NewExit(t, 1)
	}
	s.Inputs[0] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), s.RingProgramID, 100, 51), OwnerKey: PayerKey, Mint: FixtureMint}
	if shape.Entry {
		s.InputCount = 2
		s.Inputs[1] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, DefaultOwnerKey), spptest.MustNullifierPk(t, big.NewInt(8)), big.NewInt(0), 70, 52), OwnerKey: DefaultOwnerKey, Mint: FixtureMint}
	}
	return s
}

// RingNote is a data-free ring note of owner under the TXOB blinding of slot i.
func (a Audit) RingNote(t testing.TB, i int, owner [32]byte, nullifierPk *big.Int, amount uint64) Slot {
	t.Helper()
	return Slot{OwnerKey: owner, Mint: FixtureMint, Utxo: Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, owner), NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, FixtureMint), Amount: amount, Blinding: a.Blinding(t, i),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: a.RingProgramID,
	}}
}

// Spending replaces the inputs with n live ring notes of the payer.
func (a Audit) Spending(t testing.TB, n int) Audit {
	t.Helper()
	a.Inputs = slices.Clone(a.Inputs)
	for i := range a.Inputs {
		a.Inputs[i] = Input{Utxo: SpareInput(i)}
		if i < n {
			a.Inputs[i] = Input{Utxo: SpentUtxo(t, ringtest.MustSolanaPkField(t, PayerKey), spptest.MustNullifierPk(t, big.NewInt(7)), a.RingProgramID, 10, 60+int64(i)), OwnerKey: PayerKey, Mint: FixtureMint}
		}
	}
	return a
}

// DefaultBits mirrors the sealed default bits.
func (a Audit) DefaultBits() uint64 {
	return a.defaultBits()
}

// Plaintexts are the sealed regions of a transfer, a test edits them to claim what the circuit refuses.
type Plaintexts struct {
	Envelope []byte
	Records  [][]byte
	Tails    [][]byte
}

func (a Audit) Plaintexts(t testing.TB) Plaintexts {
	t.Helper()
	envelope := append(slices.Clone(a.Keys.txViewingSk[:]), byte(a.RealInputs()))
	if a.Shape.Entry {
		envelope = binary.BigEndian.AppendUint64(envelope, a.defaultBits())
		for _, input := range a.Inputs {
			envelope = append(envelope, input.entry(t)...)
		}
	}
	p := Plaintexts{Envelope: envelope, Records: make([][]byte, len(a.Outputs))}
	for i, output := range a.Outputs {
		p.Records[i] = output.Record(t)
		if a.Shape.Data {
			p.Tails = append(p.Tails, output.Tail(t))
		}
	}
	return p
}

// Seal runs the key's cipher over plaintexts, every region at its counters.
func (a Audit) Seal(t testing.TB, p Plaintexts) Stream {
	t.Helper()
	ranges := a.Shape.Ranges()
	plaintext := append(slices.Clone(p.Envelope), make([]byte, ranges.RecordOffset(0)-len(p.Envelope))...)
	plaintext = append(plaintext, slices.Concat(p.Records...)...)
	plaintext = append(plaintext, slices.Concat(p.Tails...)...)
	return Stream{Ranges: ranges, Ciphertext: a.Keys.StreamCiphertext(t, plaintext, shared.AuditEncInfo)}
}

// Open decrypts a stream the auditor read, the keystream is the zero plaintext's ciphertext.
func (k Keys) Open(t testing.TB, stream Stream) []byte {
	t.Helper()
	keystream := k.StreamCiphertext(t, make([]byte, len(stream.Ciphertext)), shared.AuditEncInfo)
	plaintext := make([]byte, len(keystream))
	for i := range plaintext {
		plaintext[i] = keystream[i] ^ stream.Ciphertext[i]
	}
	return plaintext
}

// PublishedHashes are the output hashes SPP publishes.
func (a Audit) PublishedHashes(t testing.TB) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, a.OutputCount())
	for i := range hashes {
		hashes[i] = a.Outputs[i].Utxo.Hash(t)
	}
	return hashes
}

// Claim is the part of the statement the program reads off the frame, a test moves one cell.
type Claim struct {
	NoSpend     bool
	OutputCount int
	InputCount  int
}

func (a Audit) Claim() Claim {
	return Claim{NoSpend: a.RealInputs() == 0, OutputCount: a.OutputCount(), InputCount: a.InputCount}
}

// StatementOf is what the program would hash over stream under claim.
func (a Audit) StatementOf(t testing.TB, stream Stream, claim Claim) []*big.Int {
	t.Helper()
	outputs := a.StatementOutputs(t, stream)
	head := a.Keys.AuditHead(t, a.FirstNullifier, a.RingProgramID, a.Salt, stream.Envelope(claim.InputCount))
	head.Layout = a.Layout()
	return append(head.ElementsUnder(t, shared.AuditStatementDomain), big.NewInt(ringtest.Bit(claim.NoSpend)), big.NewInt(int64(claim.OutputCount)),
		OutputChain(t, outputs), RecordChain(t, outputs), TailChain(t, outputs), big.NewInt(int64(claim.InputCount)))
}

func (a Audit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return a.StatementOf(t, a.Seal(t, a.Plaintexts(t)), a.Claim())
}

// Circuit assigns the section honestly under its own statement.
func (a Audit) Circuit(t testing.TB) *SectionCircuit {
	t.Helper()
	c := NewSectionCircuit(a.Shape)
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.Wires(a.Layout())
	c.OutputCount = a.OutputCount()
	c.InputCount = a.InputCount
	for i, output := range a.Outputs {
		c.Outputs[i] = output.Wires()
	}
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Utxo.Wires()
		if a.Shape.Entry {
			c.Entries[i] = input.EntryWires()
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

func (a Audit) Reader() AuditReader {
	return AuditReader{Transfer: a.Transfer, Shape: a.Shape, HasData: a.HasData, InputCount: a.InputCount, TreeID: OutputTreeID}
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

// ReadEntry rebuilds default input i from its evidence and accepts only an exact match, nil on any other slot.
func (r AuditReader) ReadEntry(t testing.TB, stream Stream, i int, treeID uint16, spent *big.Int) (*Note, error) {
	t.Helper()
	plaintext := r.Keys.Open(t, stream)
	_, bits := r.Envelope(t, stream)
	if bits&(1<<i) == 0 {
		return nil, nil
	}
	offset := stream.Ranges.EnvelopeHeadLen() + i*audit.EntryInputLen
	entry := plaintext[offset : offset+audit.EntryInputLen]
	note := Note{Kind: audit.KindExit, OwnerKey: [32]byte(entry[:32]), NullifierPk: new(big.Int).SetBytes(entry[32:64]), Amount: binary.BigEndian.Uint64(entry[64:72]), Mint: [32]byte(entry[72:104]), Blinding: new(big.Int).SetBytes(entry[104:136])}
	note.Hash = Utxo{
		Domain: protocol.UtxoDomain, TreeID: treeID, OwnerPkHash: ringtest.MustSolanaPkField(t, note.OwnerKey), NullifierPk: note.NullifierPk,
		Asset: ringtest.AssetField(t, note.Mint), Amount: note.Amount, Blinding: note.Blinding,
		DataHash: new(big.Int).SetBytes(entry[136:168]), RingDataHash: new(big.Int).SetBytes(entry[168:200]), RingProgramID: big.NewInt(0),
	}.Hash(t)
	if note.Hash.Cmp(spent) != 0 {
		return nil, fmt.Errorf("input %d: the evidence rebuilds no spent commitment", i)
	}
	return &note, nil
}
