package ringaudit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// PackedAudit is a packed audit witness with every derived value explicit, the statement rebuilds from its fields.
type PackedAudit struct {
	Transfer
	// NOut is the published output count.
	NOut      int
	Outputs   []Utxo
	OwnerKeys [][32]byte
	Layout    Layout
}

// PackedAuditOf publishes nOut outputs, the exits slots leaving the ring and ring outputs carrying data elsewhere.
func PackedAuditOf(t testing.TB, capacity, nOut int, exits ...int) PackedAudit {
	t.Helper()
	p := PackedAudit{
		Transfer:  newTransfer(t),
		NOut:      nOut,
		Outputs:   make([]Utxo, capacity),
		OwnerKeys: make([][32]byte, capacity),
	}
	for i := range capacity {
		switch {
		case i >= p.NOut:
			p.Outputs[i] = unpublished()
		case slices.Contains(exits, i):
			p.OwnerKeys[i] = ringtest.Repeat(0xe5)
			p.Outputs[i] = p.NewExit(t, i).Utxo
		default:
			p.OwnerKeys[i] = ringtest.Repeat(0xb2 + byte(i))
			p.Outputs[i] = p.NewRingOutput(t, i)
		}
	}
	p.Layout.Exits = hasExit(p.Outputs[:p.NOut])
	return p
}

// NewRingOutput is ring output i of owner key OwnerKeys[i], carrying data.
func (p PackedAudit) NewRingOutput(t testing.TB, i int) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: OutputTreeID, OwnerPkHash: ringtest.MustSolanaPkField(t, p.OwnerKeys[i]),
		NullifierPk: spptest.MustNullifierPk(t, big.NewInt(20+int64(i))), Asset: ringtest.AssetField(t, ringtest.Repeat(0x0a)),
		Amount: 100 + uint64(i), Blinding: p.RingBlinding(t, i),
		DataHash: big.NewInt(0x61 + int64(i)), RingDataHash: big.NewInt(0x71 + int64(i)), RingProgramID: p.RingProgramID,
	}
}

// RingBlinding is the TXRB blinding of slot i under the CRRC secret of its CRAS slot secret.
func (p PackedAudit) RingBlinding(t testing.TB, i int) *big.Int {
	t.Helper()
	secret := ringprotocol.PackedSlotSecret(t, p.Keys.txViewingSk, p.Salt, i, p.FirstNullifier)
	return ringprotocol.RingBlinding(t, p.FirstNullifier, ringprotocol.ConfidentialRingSecret(t, secret), i)
}

// Statement mirrors the packed audit preimage, head ‖ output_chain, disclosure_chain.
func (p PackedAudit) Statement(t testing.TB) []*big.Int {
	t.Helper()
	return PackedStatement(t, p.AuditHead(t, p.Layout), p.StatementOutputs(t), p.Disclosure(t))
}

func (p PackedAudit) StatementOutputs(t testing.TB) []StatementOutput {
	t.Helper()
	outputs := make([]StatementOutput, p.NOut)
	for i, output := range p.Outputs[:p.NOut] {
		outputs[i] = StatementOutput{Hash: output.Hash(t)}
	}
	return outputs
}

// Disclosure is the enciphered packed disclosure under p.Layout.
func (p PackedAudit) Disclosure(t testing.TB) []*big.Int {
	t.Helper()
	fields := p.seedOut(p.Layout)
	for i, output := range p.Outputs[:p.NOut] {
		keyAndAmount := make([]byte, 40)
		if output.isUtxo() {
			keyAndAmount = binary.BigEndian.AppendUint64(slices.Clone(p.OwnerKeys[i][:]), output.Amount)
		}
		if !p.Layout.Escrow {
			fields = append(fields, live(output, output.NullifierPk))
		}
		fields = append(fields, live(output, output.Asset))
		if !p.Layout.DataFree {
			fields = append(fields, live(output, output.DataHash), live(output, output.RingDataHash))
		}
		fields = append(fields, ringprotocol.PackDisclosure(keyAndAmount)...)
	}
	return p.Keys.Disclose(t, p.Salt, fields)
}

// Circuit is the audit assignment proving the statement.
func (p PackedAudit) Circuit(t testing.TB) *audit.PackedAuditCircuit {
	t.Helper()
	c, err := audit.NewPackedAuditCircuit(len(p.Outputs))
	if err != nil {
		t.Fatal(err)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, p.Statement(t))
	c.AuditWires = p.wires(p.Layout)
	c.NOut = p.NOut
	for i, output := range p.Outputs {
		c.Outputs[i] = output.Wires()
		ringtest.SetBytes(c.OwnerKeys[i][:], p.OwnerKeys[i][:])
	}
	return c
}
