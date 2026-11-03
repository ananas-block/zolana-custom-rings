package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AnonymousOutput is the host twin of audit.AnonymousOutputWires.
type AnonymousOutput struct {
	Utxo     Utxo
	OwnerKey [32]byte
}

type AnonymousAudit struct {
	Transfer
	Shape             audit.AnonymousAuditShape
	Outputs           []AnonymousOutput
	SenderKey         [32]byte
	SenderNullifierPk *big.Int
	PrivateTxBlinding *big.Int
	PartyIdentities   [3]*big.Int
	InputCount        int
	Inputs            []Utxo
	Layout            Layout
}

const (
	kindPayment = iota
	kindChange
	kindExit
	kindDummy
)

var anonymousOutputs = map[int][]int{
	2: {kindPayment, kindChange},
	4: {kindPayment, kindPayment, kindExit, kindChange},
	8: {kindPayment, kindPayment, kindPayment, kindExit, kindChange, kindPayment, kindDummy, kindDummy},
}

// NewAnonymousAudit spends two sender UTXOs, input 1 from the default ring on an entry shape.
func NewAnonymousAudit(t testing.TB, shape audit.AnonymousAuditShape) AnonymousAudit {
	t.Helper()
	a := AnonymousAudit{
		Transfer:          newTransfer(t),
		Shape:             shape,
		SenderKey:         ringtest.Repeat(0xa1),
		SenderNullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		PrivateTxBlinding: big.NewInt(0x5b1d),
		PartyIdentities:   [3]*big.Int{big.NewInt(11), big.NewInt(12), big.NewInt(0)},
		InputCount:        2,
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
			a.Outputs = append(a.Outputs, AnonymousOutput{Utxo: a.newDummy(t, i).Utxo, OwnerKey: ringtest.Repeat(0xd1 + byte(i))})
		}
	}
	a.Layout = Layout{FullOpenings: shape.FullOpenings}
	return a
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
	return DeliverySlot{Index: i, OwnerKey: a.SenderKey, NullifierPk: a.SenderNullifierPk, AssetAddress: ringtest.Repeat(0x0a), Amount: 15}
}

// NewPayment is a ring output to slot's owner key.
func (a AnonymousAudit) NewPayment(t testing.TB, slot DeliverySlot) AnonymousOutput {
	t.Helper()
	return AnonymousOutput{Utxo: a.ringUtxo(t, slot), OwnerKey: slot.OwnerKey}
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
	return AnonymousTail{InputCount: a.InputCount, PrivateTxHash: a.PrivateTxHash(t), PartyIdentities: a.PartyIdentities}
}

func (a AnonymousAudit) StatementOutputs(t testing.TB, stream Stream) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, len(a.Outputs))
	for i, output := range a.Outputs {
		length := audit.AnonymousRecordLen
		if output.Utxo.isExit() {
			length = audit.ExitRecordLen
		}
		outputs[i] = StatementOutput{Hash: output.Utxo.Hash(t), Exit: output.Utxo.isExit(), Ciphertext: stream.Record(i, length)}
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
	first := spptest.MustFieldBytes(t, published[0].spentHash(t))
	evidence = first[:]
	for _, input := range published[1:] {
		evidence = append(evidence, inputPrefix(t, input.spentHash(t))...)
	}
	return evidence
}

func entryInput(t testing.TB, input Utxo) []byte {
	t.Helper()
	if !input.isUtxo() {
		return make([]byte, audit.EntryInputLen)
	}
	asset, blinding := spptest.MustFieldBytes(t, input.Asset), spptest.MustFieldBytes(t, input.Blinding)
	return slices.Concat(binary.BigEndian.AppendUint64(nil, input.Amount), asset[:], blinding[:])
}

// Circuit is the section assignment proving the statement.
func (a AnonymousAudit) Circuit(t testing.TB) *AnonymousCircuit {
	t.Helper()
	c := NewAnonymousCircuit(a.Shape)
	c.PublicInputHash = spptest.MustHashChain4(t, a.Statement(t))
	c.AuditWires = a.Wires(a.Layout)
	for i, output := range a.Outputs {
		c.Outputs[i] = audit.AnonymousOutputWires{Output: output.Utxo.Wires()}
		ringtest.SetBytes(c.Outputs[i].OwnerKey[:], output.OwnerKey[:])
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
