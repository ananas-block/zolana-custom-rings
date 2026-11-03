package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// DeliveredAudit is a delivered confidential audit witness with every derived value explicit.
type DeliveredAudit struct {
	Transfer
	Outputs                []DeliveredOutput
	Layout                 Layout
	InputClass, InputCount int
	// Inputs is nil on a section alone, no evidence then enters the stream.
	Inputs  []Utxo
	Omitted int
}

// NewDeliveredAudit fills capacity slots with ring outputs, then one exit and one dummy.
func NewDeliveredAudit(t testing.TB, capacity int) DeliveredAudit {
	t.Helper()
	return DeliveredAuditOf(t, capacity, capacity-2)
}

// DeliveredAuditOf delivers ring outputs to every slot but the exits and a last dummy.
func DeliveredAuditOf(t testing.TB, capacity int, exits ...int) DeliveredAudit {
	t.Helper()
	d := DeliveredAudit{Transfer: newTransfer(t), Outputs: make([]DeliveredOutput, capacity)}
	for i := range capacity {
		switch {
		case i == capacity-1:
			d.Outputs[i] = d.newDummy(t, i)
		case slices.Contains(exits, i):
			d.Outputs[i] = d.NewExit(t, i)
		default:
			d.Outputs[i] = d.NewConfidentialOutput(t, i)
		}
	}
	return d
}

func (d DeliveredAudit) AllDummies(t testing.TB) DeliveredAudit {
	t.Helper()
	for i := range d.Outputs {
		d.Outputs[i] = d.newDummy(t, i)
	}
	return d
}

// NewConfidentialOutput delivers slot i to fixture recipient i mod 3.
func (d DeliveredAudit) NewConfidentialOutput(t testing.TB, i int) DeliveredOutput {
	t.Helper()
	return d.NewRingOutput(t, Recipient(t, byte(i%3), i, 100+uint64(i)))
}

// Omit cuts the last n slots to omitted dummies, each published slot keeps its index.
func (d DeliveredAudit) Omit(t testing.TB, n int) DeliveredAudit {
	t.Helper()
	d.Outputs = slices.Clone(d.Outputs)
	for i := len(d.Outputs) - n; i < len(d.Outputs); i++ {
		d.Outputs[i] = DeliveredOutput{Utxo: Dummy(0, big.NewInt(0))}
	}
	d.Omitted = n
	return d
}

func (d DeliveredAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return DeliveredStatement(t, d.Head(t), d.StatementOutputs(t))
}

func (d DeliveredAudit) Head(t testing.TB) AuditHead {
	t.Helper()
	return d.AuditHead(t, d.Layout, d.Stream(t).Envelope(d.evidenceCount()))
}

func (d DeliveredAudit) Ranges() audit.StreamRanges {
	return audit.ConfidentialRanges(d.InputClass, len(d.Outputs))
}

func (d DeliveredAudit) evidenceCount() int {
	if d.Inputs == nil {
		return 0
	}
	return d.InputCount
}

func (d DeliveredAudit) OutputCount() int {
	return len(d.Outputs) - d.Omitted
}

func (d DeliveredAudit) Stream(t testing.TB) Stream {
	t.Helper()
	var evidence []byte
	for _, input := range d.Inputs[:d.evidenceCount()] {
		evidence = append(evidence, inputEvidence(t, input)...)
	}
	records := make([][]byte, len(d.Outputs))
	for i, output := range d.Outputs {
		if output.Utxo.isExit() {
			records[i] = exitRecord(t, output.Utxo)
		}
	}
	return d.Keys.SealAuditorStream(t, d.Ranges(), evidence, records)
}

func (d DeliveredAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	bodyLen, recordLen := shared.BodyLen, audit.ExitRecordLen
	if d.Layout.Escrow {
		bodyLen, recordLen = shared.EscrowBodyLen, audit.EscrowExitRecordLen
	}
	stream := d.Stream(t)
	outputs := make([]StatementOutput, len(d.Outputs))
	for i, output := range d.Outputs {
		ciphertext := output.Body[:bodyLen]
		if output.Utxo.isExit() {
			ciphertext = stream.Record(i, recordLen)
		}
		outputs[i] = output.statementOutput(t, ciphertext)
		outputs[i].Omitted = i >= d.OutputCount()
	}
	return outputs
}

// Utxos is the opening of every output slot.
func (d DeliveredAudit) Utxos() []Utxo {
	utxos := make([]Utxo, len(d.Outputs))
	for i, output := range d.Outputs {
		utxos[i] = output.Utxo
	}
	return utxos
}

// Circuit is the section assignment proving the statement.
func (d DeliveredAudit) Circuit(t testing.TB) *DeliveredCircuit {
	t.Helper()
	c := NewDeliveredCircuit(d.InputClass, len(d.Outputs))
	c.PublicInputHash = spptest.MustHashChain4(t, d.Statement(t))
	c.AuditWires = d.Wires(d.Layout)
	c.OutputCount = d.OutputCount()
	for i, output := range d.Outputs {
		c.Outputs[i] = output.Wires()
	}
	return c
}

// DeliveredSenderAudit is a delivered audit of the in-proof owner rail spending two inputs of the sender.
type DeliveredSenderAudit struct {
	DeliveredAudit
	Shape             SenderShape
	SenderKey         [32]byte
	PrivateTxBlinding *big.Int
}

func NewDeliveredSenderAudit(t testing.TB, shape SenderShape) DeliveredSenderAudit {
	t.Helper()
	d := DeliveredSenderAudit{
		DeliveredAudit:    NewDeliveredAudit(t, shape.Outputs),
		Shape:             shape,
		SenderKey:         ringtest.Repeat(0xa1),
		PrivateTxBlinding: big.NewInt(0x5b1d),
	}
	d.InputClass, d.InputCount, d.Inputs = shape.Inputs, 2, make([]Utxo, shape.Inputs)
	for i := range d.Inputs {
		d.Inputs[i] = spareInput(i)
	}
	nullifierPk := spptest.MustNullifierPk(t, big.NewInt(7))
	d.Inputs[0] = spentUtxo(t, d.Sender(t), nullifierPk, d.RingProgramID, 100, 51)
	d.Inputs[1] = spentUtxo(t, d.Sender(t), nullifierPk, d.RingProgramID, 60, 52)
	return d
}

// Sender is the owner identity of SenderKey.
func (d DeliveredSenderAudit) Sender(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, d.SenderKey)
}

// PrivateTxHash is SPP's private transaction hash over the slots, with no address input.
func (d DeliveredSenderAudit) PrivateTxHash(t testing.TB) *big.Int {
	t.Helper()
	outputs := make([]Utxo, len(d.Outputs))
	for i, output := range d.Outputs {
		outputs[i] = output.Utxo
	}
	return spptest.MustPrivateTxHash(t, spentHashes(t, d.Inputs), spentHashes(t, outputs), nil, d.PrivateTxBlinding)
}

func (d DeliveredSenderAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return DeliveredSenderStatement(t, d.Head(t), d.StatementOutputs(t), d.InputCount, d.PrivateTxHash(t), d.Sender(t))
}

func (d DeliveredSenderAudit) Circuit(t testing.TB) *DeliveredSenderCircuit {
	t.Helper()
	c := NewDeliveredSenderCircuit(d.Shape)
	c.DeliveredCircuit = *d.DeliveredAudit.Circuit(t)
	c.PublicInputHash = spptest.MustHashChain4(t, d.Statement(t))
	c.InputCount = d.InputCount
	c.Sender = d.Sender(t)
	c.PrivateTxHash = d.PrivateTxHash(t)
	c.PrivateTxBlinding = d.PrivateTxBlinding
	for i, input := range d.Inputs {
		c.Inputs[i] = input.Wires()
	}
	return c
}
