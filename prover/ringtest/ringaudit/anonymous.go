package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AnonymousOutput is the host twin of audit.AnonymousOutputWires.
type AnonymousOutput struct {
	Utxo            Utxo
	OwnerKey        [32]byte
	RecipientKey    [32]byte
	AddressRevision uint64
	Mint            [32]byte
	Body            [shared.RecipientBodyLen]byte
	// Tag and TagPreimage read zero when nil, a live slot's tag derives from its slot secret.
	Tag, TagPreimage *big.Int
}

type AnonymousAudit struct {
	Transfer
	Shape                 audit.AnonymousAuditShape
	Outputs               []AnonymousOutput
	SenderKey             [32]byte
	SenderNullifierPk     *big.Int
	SenderViewingKey      [32]byte
	SenderAddressRevision uint64
	PrivateTxBlinding     *big.Int
	PartyIdentities       [3]*big.Int
	InputCount            int
	Inputs                []Utxo
	Layout                Layout
	Signers               []*big.Int
	Omitted               int
	// Bound address hash per owner identity.
	Rows map[string]*big.Int
}

const (
	kindPayment = iota
	kindChange
	kindExit
	kindDummy
)

// anonymousOutputs lead with change, the bundle holds it in slot 0.
var anonymousOutputs = map[int][]int{
	2: {kindChange, kindPayment},
	4: {kindChange, kindPayment, kindExit, kindPayment},
	8: {kindChange, kindPayment, kindPayment, kindExit, kindPayment, kindPayment, kindDummy, kindDummy},
}

// NewAnonymousAudit spends two sender UTXOs, input 1 from the default ring on an entry shape.
func NewAnonymousAudit(t testing.TB, shape audit.AnonymousAuditShape) AnonymousAudit {
	t.Helper()
	a := AnonymousAudit{
		Transfer:              newTransfer(t),
		Shape:                 shape,
		SenderKey:             ringtest.Repeat(0xa1),
		SenderNullifierPk:     spptest.MustNullifierPk(t, big.NewInt(7)),
		SenderViewingKey:      ringprotocol.XPublicKey(t, ringtest.Scalar(0x77)),
		SenderAddressRevision: 1,
		PrivateTxBlinding:     big.NewInt(0x5b1d),
		PartyIdentities:       [3]*big.Int{big.NewInt(11), big.NewInt(12), big.NewInt(0)},
		InputCount:            2,
		Rows:                  map[string]*big.Int{},
	}
	a.Inputs = make([]Utxo, shape.InputClass)
	for i := range a.Inputs {
		a.Inputs[i] = spareInput(i)
	}
	a.Inputs[0] = a.SenderUtxo(t, a.RingProgramID, 100, 51)
	ring := a.RingProgramID
	if shape.FullOpenings {
		ring = big.NewInt(0)
	}
	a.Inputs[1] = a.SenderUtxo(t, ring, 60, 52)
	a.Rows[a.SenderPkHash(t).String()] = a.senderAddress(t).Hash(t)
	payments := 0
	for i, kind := range anonymousOutputs[shape.Outputs] {
		switch kind {
		case kindPayment:
			a.Outputs = append(a.Outputs, a.NewPayment(t, Recipient(t, byte(payments%3), i, 30+uint64(i))))
			payments++
		case kindChange:
			a.Outputs = append(a.Outputs, a.NewPayment(t, a.Change(t, i)))
		case kindExit:
			a.Outputs = append(a.Outputs, a.NewAnonymousExit(t, i))
		case kindDummy:
			a.Outputs = append(a.Outputs, a.newAnonymousDummy(t, i))
		}
	}
	a.Layout = Layout{FullOpenings: shape.FullOpenings}
	return a
}

func (a AnonymousAudit) senderAddress(t testing.TB) ringregistry.Address {
	t.Helper()
	return ringregistry.Address{RingID: a.RingProgramID, Member: a.SenderPkHash(t), NullifierPk: a.SenderNullifierPk, ViewingKey: a.SenderViewingKey, Revision: a.SenderAddressRevision}
}

// IsChange mirrors the exact address match of audit.AuditWires.DeliverRecipients.
func (a AnonymousAudit) IsChange(t testing.TB, output AnonymousOutput) bool {
	t.Helper()
	return output.Utxo.isRingOutput() && output.Utxo.OwnerPkHash.Cmp(a.SenderPkHash(t)) == 0 && output.Utxo.NullifierPk.Cmp(a.SenderNullifierPk) == 0 && output.RecipientKey == a.SenderViewingKey
}

func (a AnonymousAudit) OutputCount() int {
	return len(a.Outputs) - a.Omitted
}

// Omit cuts the last n slots to omitted dummies, each published slot keeps its index.
func (a AnonymousAudit) Omit(t testing.TB, n int) AnonymousAudit {
	t.Helper()
	a.Outputs = slices.Clone(a.Outputs)
	for i := len(a.Outputs) - n; i < len(a.Outputs); i++ {
		a.Outputs[i] = AnonymousOutput{Utxo: Dummy(0, big.NewInt(0))}
	}
	a.Omitted = n
	return a
}

func (a AnonymousAudit) AllDummies(t testing.TB) AnonymousAudit {
	t.Helper()
	for i := range a.Outputs {
		a.Outputs[i] = a.newAnonymousDummy(t, i)
	}
	return a
}

func (a AnonymousAudit) newAnonymousDummy(t testing.TB, i int) AnonymousOutput {
	t.Helper()
	preimage := big.NewInt(0xd00 + int64(i))
	dummy := AnonymousOutput{Utxo: a.newDummy(t, i).Utxo, OwnerKey: ringtest.Repeat(0xd1 + byte(i)), TagPreimage: preimage, Tag: ringprotocol.RecipientTag(t, preimage)}
	for j := range dummy.Body {
		dummy.Body[j] = 0xd0 + byte(j)
	}
	return dummy
}

func (a AnonymousAudit) AtInputCount(count int) AnonymousAudit {
	a.InputCount = count
	a.Inputs = slices.Clone(a.Inputs)
	for i := count; i < len(a.Inputs); i++ {
		a.Inputs[i] = spareInput(i)
	}
	return a
}

// SenderPkHash is the owner identity of the hidden sender.
func (a AnonymousAudit) SenderPkHash(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, a.SenderKey)
}

// SenderUtxo is a UTXO of the hidden sender in the given ring, 0 for the default ring.
func (a AnonymousAudit) SenderUtxo(t testing.TB, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return spentUtxo(t, a.SenderPkHash(t), a.SenderNullifierPk, ringID, amount, blinding)
}

// SpentUtxo is a data-free input of owner in the given ring, 0 for the default ring.
func SpentUtxo(t testing.TB, ownerPkHash, nullifierPk, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return spentUtxo(t, ownerPkHash, nullifierPk, ringID, amount, blinding)
}

// SpareInput is a slot past the published count.
func SpareInput(i int) Utxo {
	return spareInput(i)
}

// SpentHashes is the private_tx_hash entry of every slot, zero off a UTXO.
func SpentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	return spentHashes(t, utxos)
}

// Utxos is the opening of every output slot.
func (a AnonymousAudit) Utxos() []Utxo {
	return anonymousUtxos(a.Outputs)
}

// spentUtxo is a data-free input of owner in the given ring.
func spentUtxo(t testing.TB, ownerPkHash, nullifierPk, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: 3, OwnerPkHash: ownerPkHash, NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, ringtest.Repeat(0x0a)), Amount: amount, Blinding: big.NewInt(blinding),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}
}

// Change is the sender's change slot i.
func (a AnonymousAudit) Change(t testing.TB, i int) DeliverySlot {
	t.Helper()
	return DeliverySlot{Index: i, RecipientKey: a.SenderViewingKey, OwnerKey: a.SenderKey, NullifierPk: a.SenderNullifierPk, AssetAddress: ringtest.Repeat(0x0a), Amount: 15}
}

// NewPayment is a ring output to slot's owner at revision 1, enrolled in Rows, sealed unless it reaches the sender's exact address.
func (a AnonymousAudit) NewPayment(t testing.TB, slot DeliverySlot) AnonymousOutput {
	t.Helper()
	utxo := a.ringUtxo(t, slot)
	output := AnonymousOutput{Utxo: utxo, OwnerKey: slot.OwnerKey, RecipientKey: slot.RecipientKey, AddressRevision: 1, Mint: slot.AssetAddress}
	if a.IsChange(t, output) {
		output.AddressRevision = a.SenderAddressRevision
		return output
	}
	a.Rows[utxo.OwnerPkHash.String()] = ringregistry.Address{RingID: a.RingProgramID, Member: utxo.OwnerPkHash, NullifierPk: slot.NullifierPk, ViewingKey: slot.RecipientKey, Revision: 1}.Hash(t)
	secret := a.DeliveredSlotSecret(t, slot.RecipientKey, slot.Index)
	output.Body = ringprotocol.RecipientBody{Blinding: utxo.Blinding, Amount: slot.Amount, Mint: slot.AssetAddress}.Seal(t, secret)
	output.Tag = ringprotocol.RecipientTag(t, secret)
	return output
}

// Reseal rebuilds slot i's body over its opening at its recipient key, a live ring slot's only valid body.
func (a AnonymousAudit) Reseal(t testing.TB, i int) {
	t.Helper()
	output := &a.Outputs[i]
	if !output.Utxo.isRingOutput() || a.IsChange(t, *output) {
		return
	}
	secret := a.DeliveredSlotSecret(t, output.RecipientKey, i)
	output.Body = ringprotocol.RecipientBody{Blinding: output.Utxo.Blinding, Amount: output.Utxo.Amount, Mint: output.Mint}.Seal(t, secret)
	output.Tag = ringprotocol.RecipientTag(t, secret)
}

// NewAnonymousExit carries the exit owner's key, the record omits it.
func (a AnonymousAudit) NewAnonymousExit(t testing.TB, i int) AnonymousOutput {
	t.Helper()
	return AnonymousOutput{Utxo: a.NewExit(t, i).Utxo, OwnerKey: ExitOwnerKey}
}

// PrivateTxHash is SPP's private transaction hash over the slots, with no address input.
func (a AnonymousAudit) PrivateTxHash(t testing.TB) *big.Int {
	t.Helper()
	return spptest.MustPrivateTxHash(t, spentHashes(t, a.Inputs), spentHashes(t, anonymousUtxos(a.Outputs)), nil, a.PrivateTxBlinding)
}

func (a AnonymousAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return a.StatementOver(t, a.Stream(t))
}

func (a AnonymousAudit) StatementOver(t testing.TB, stream Stream) []*big.Int {
	t.Helper()
	return AnonymousStatement(t, a.AuditHead(t, a.Layout, stream.Envelope(a.InputCount)), a.StatementOutputs(t, stream), a.Tail(t))
}

func (a AnonymousAudit) Tail(t testing.TB) AnonymousTail {
	t.Helper()
	return AnonymousTail{
		OutputCount: a.OutputCount(), BundleDigest: ringprotocol.EnvelopeDigest(t, a.Bundle(t)), BundleTag: a.BundleTag(t), InputCount: a.InputCount, PrivateTxHash: a.PrivateTxHash(t), PartyIdentities: a.PartyIdentities,
		SignerCount: len(a.Signers), SignerChain: SignerChain(t, a.Signers, a.signerSlots()),
	}
}

func (a AnonymousAudit) signerSlots() int {
	if a.Shape.FullOpenings {
		return 0
	}
	return a.Shape.InputClass
}

func (a AnonymousAudit) BundleTag(t testing.TB) *big.Int {
	t.Helper()
	return ringprotocol.SenderBundleTag(t, a.DeliveredSlotSecret(t, a.SenderViewingKey, a.OutputCount()))
}

func (a AnonymousAudit) Bundle(t testing.TB) []byte {
	t.Helper()
	bundle := ringprotocol.SenderBundle{OutputSeed: a.SeedOut, RecipientKeys: make([][32]byte, a.OutputCount())}
	for i, output := range a.Outputs[:a.OutputCount()] {
		switch {
		case a.IsChange(t, output) && i == 0:
			bundle.Mint, bundle.Amount = output.Mint, output.Utxo.Amount
		case a.IsChange(t, output) && i == 1:
			bundle.SolAmount = output.Utxo.Amount
		case output.Utxo.isRingOutput() && !a.IsChange(t, output):
			bundle.RecipientKeys[i] = output.RecipientKey
		}
	}
	return bundle.Seal(t, a.DeliveredSlotSecret(t, a.SenderViewingKey, a.OutputCount()))
}

func (a AnonymousAudit) StatementOutputs(t testing.TB, stream Stream) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(a.Outputs))
	for i, output := range a.Outputs {
		length := audit.AnonymousRecordLen
		if output.Utxo.isExit() {
			length = audit.ExitRecordLen
		}
		outputs[i] = StatementOutput{Hash: output.Utxo.Hash(t), Exit: output.Utxo.isExit(), Ciphertext: stream.Record(i, length), Change: a.IsChange(t, output), Omitted: i >= a.OutputCount()}
		if !outputs[i].Omitted && !outputs[i].Exit && !outputs[i].Change {
			outputs[i].Body = slices.Clone(output.Body[:])
			outputs[i].Tag = output.Tag
		}
	}
	return outputs
}

func (a AnonymousAudit) Stream(t testing.TB) Stream {
	t.Helper()
	return a.StreamOf(t, a.Evidence(t), a.Records(t))
}

func (a AnonymousAudit) StreamOf(t testing.TB, evidence []byte, records [][]byte) Stream {
	t.Helper()
	return a.Keys.SealAuditorStream(t, a.Shape.Ranges(), evidence, records)
}

func (a AnonymousAudit) Records(t testing.TB) [][]byte {
	t.Helper()
	records := make([][]byte, len(a.Outputs))
	for i, output := range a.Outputs {
		switch {
		case output.Utxo.isRingOutput():
			records[i] = slices.Concat(output.OwnerKey[:], exitRecord(t, output.Utxo))
		case output.Utxo.isExit():
			records[i] = exitRecord(t, output.Utxo)
		default:
			records[i] = make([]byte, audit.AnonymousRecordLen)
		}
	}
	return records
}

func (a AnonymousAudit) Evidence(t testing.TB) []byte {
	t.Helper()
	published := a.Inputs[:a.InputCount]
	var evidence []byte
	if a.Shape.FullOpenings {
		nullifierPk := spptest.MustFieldBytes(t, a.Inputs[0].NullifierPk)
		evidence = slices.Concat(a.SenderKey[:], nullifierPk[:])
		for _, input := range published {
			evidence = append(evidence, entryInput(t, input)...)
		}
		return evidence
	}
	for _, input := range published {
		evidence = append(evidence, inputEvidence(t, input)...)
	}
	return evidence
}

func entryInput(t testing.TB, input Utxo) []byte {
	t.Helper()
	if !input.isUtxo() {
		return make([]byte, audit.EntryInputLen)
	}
	asset, blinding := spptest.MustFieldBytes(t, input.Asset), spptest.MustFieldBytes(t, input.Blinding)
	return slices.Concat(inputEvidence(t, input), binary.BigEndian.AppendUint64(nil, input.Amount), asset[:], blinding[:])
}

// A slot without a mint opens the zero chunks.
func (o AnonymousOutput) Wires() audit.AnonymousOutputWires {
	w := audit.AnonymousOutputWires{Output: o.Utxo.Wires(), AddressRevision: o.AddressRevision, Tag: 0, TagPreimage: 0}
	if o.Tag != nil {
		w.Tag = o.Tag
	}
	if o.TagPreimage != nil {
		w.TagPreimage = o.TagPreimage
	}
	ringtest.SetBytes(w.OwnerKey[:], o.OwnerKey[:])
	ringtest.SetBytes(w.RecipientKey[:], o.RecipientKey[:])
	ringtest.SetBytes(w.Body[:], o.Body[:])
	chunks := protocol.MintChunks(o.Mint)
	w.MintChunks = [2]frontend.Variable{chunks[0], chunks[1]}
	return w
}

func (a AnonymousAudit) SenderAddressWires(t testing.TB) audit.SenderAddress {
	t.Helper()
	w := audit.SenderAddress{SenderNullifierPk: a.SenderNullifierPk, SenderAddressRevision: a.SenderAddressRevision, SenderBundleTag: a.BundleTag(t)}
	ringtest.SetBytes(w.SenderViewingKey[:], a.SenderViewingKey[:])
	return w
}

func (a AnonymousAudit) Row(member *big.Int) *big.Int {
	if row, ok := a.Rows[member.String()]; ok {
		return row
	}
	return big.NewInt(0)
}

func (a AnonymousAudit) SignerWires() []frontend.Variable {
	cells := make([]frontend.Variable, a.signerSlots())
	for i := range cells {
		cells[i] = 0
		if i < len(a.Signers) {
			cells[i] = a.Signers[i]
		}
	}
	return cells
}

// Circuit is the section assignment proving the statement.
func (a AnonymousAudit) Circuit(t testing.TB) *AnonymousCircuit {
	t.Helper()
	c := NewAnonymousCircuit(a.Shape)
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.Wires(a.Layout)
	c.OutputCount = a.OutputCount()
	for i, output := range a.Outputs {
		c.Outputs[i] = output.Wires()
		c.OwnerRows[i] = a.Row(output.Utxo.OwnerPkHash)
	}
	c.PrivateTxHash = a.PrivateTxHash(t)
	c.PrivateTxBlinding = a.PrivateTxBlinding
	if a.Shape.FullOpenings {
		ringtest.SetBytes(c.SenderKey, a.SenderKey[:])
	}
	c.InputCount = a.InputCount
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Wires()
	}
	for i, party := range a.PartyIdentities {
		c.PartyIdentities[i] = party
	}
	c.SignerCount = len(a.Signers)
	copy(c.Signers, a.SignerWires())
	c.SenderAddress = a.SenderAddressWires(t)
	c.SenderRow = a.Row(a.SenderPkHash(t))
	return c
}

func anonymousUtxos(outputs []AnonymousOutput) []Utxo {
	utxos := make([]Utxo, len(outputs))
	for i, output := range outputs {
		utxos[i] = output.Utxo
	}
	return utxos
}

func spentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(utxos))
	for i, utxo := range utxos {
		hashes[i] = utxo.spentHash(t)
	}
	return hashes
}

func spareInput(i int) Utxo {
	return Dummy(3, big.NewInt(0x9000+int64(i)))
}
