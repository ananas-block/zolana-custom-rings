package audit_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Each case changes one value of an honest packed transfer and rebuilds the statement around it.
func TestPackedAuditRefusals(t *testing.T) {
	compilePacked(t, 2)
	c := compilePacked(t, 4)
	unclamped := ringaudit.DefaultKeys(t).TxViewingSk()
	unclamped[0] |= 1
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.PackedAudit)
	}{
		{"exit blinding of another slot", func(p *ringaudit.PackedAudit) { p.Outputs[1].Blinding = p.Blinding(t, 0) }},
		{"ring output blinding of another slot", func(p *ringaudit.PackedAudit) { p.Outputs[2].Blinding = p.Blinding(t, 0) }},
		{"disclosed key of another owner", func(p *ringaudit.PackedAudit) { p.OwnerKeys[0][0] ^= 1 }},
		{"unclamped transaction secret", func(p *ringaudit.PackedAudit) {
			p.Transfer = p.WithKeys(t, p.Keys.WithRawTxScalar(t, unclamped))
			for i := range p.NOut {
				p.Outputs[i].Blinding = p.Blinding(t, i)
			}
		}},
		{"data-free layout over a data hash", func(p *ringaudit.PackedAudit) {
			withoutData(p)
			p.Outputs[0].DataHash = big.NewInt(5)
		}},
		{"data-free layout over a ring data hash", func(p *ringaudit.PackedAudit) {
			withoutData(p)
			p.Outputs[0].RingDataHash = big.NewInt(5)
		}},
		{"SeedOut omitted with an exit published", func(p *ringaudit.PackedAudit) { p.Layout.Exits = false }},
		{"SeedOut published without an exit", func(p *ringaudit.PackedAudit) {
			*p = ringaudit.PackedAuditOf(t, 4, 3)
			p.Layout.Exits = true
		}},
		{"full openings flag on a packed key", func(p *ringaudit.PackedAudit) { p.Layout.FullOpenings = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := ringaudit.NewPackedAudit(t, 4)
			tc.mutate(&p)
			c.refuse(t, p.Circuit(t))
		})
	}

	// The program reads key escrow off the config, a disclosure without nullifier keys fails a statement that clears it.
	t.Run("nullifier keys omitted with the escrow bit clear", func(t *testing.T) {
		p := ringaudit.NewPackedAudit(t, 4)
		escrowed := p
		escrowed.Layout.Escrow = true
		c.refuseStatementOf(t, p.Circuit(t),
			ringaudit.PackedStatement(t, p.AuditHead(t, p.Layout), p.StatementOutputs(t), escrowed.Disclosure(t)))
	})

	t.Run("layout value past the four flags", func(t *testing.T) {
		p := ringaudit.NewPackedAudit(t, 4)
		head := p.AuditHead(t, p.Layout)
		head.Layout |= 1 << 4
		circuit := p.Circuit(t)
		circuit.Layout = head.Layout
		setPublicInput(circuit, spptest.MustHashChain4(t, ringaudit.PackedStatement(t, head, p.StatementOutputs(t), p.Disclosure(t))))
		c.refuse(t, circuit)
	})
}

// Every flag value solves at every published count, the exit in the last published slot.
func TestPackedAuditSolvesEveryLayout(t *testing.T) {
	c := compilePacked(t, 4)
	packedFlags := audit.LayoutExits | audit.LayoutEscrow | audit.LayoutDataFree
	for value := range packedFlags + 1 {
		layout := ringaudit.Layout{Exits: value&audit.LayoutExits != 0, Escrow: value&audit.LayoutEscrow != 0, DataFree: value&audit.LayoutDataFree != 0}
		for nOut := 1; nOut <= 4; nOut++ {
			t.Run(fmt.Sprintf("%+v/%d", layout, nOut), func(t *testing.T) {
				p := ringaudit.PackedAuditOf(t, 4, nOut)
				if layout.Exits {
					p = ringaudit.PackedAuditOf(t, 4, nOut, nOut-1)
				}
				if layout.DataFree {
					withoutData(&p)
				}
				p.Layout = layout
				c.requireSolved(t, p.Circuit(t))
			})
		}
	}
}

func withoutData(p *ringaudit.PackedAudit) {
	for i := range p.Outputs[:p.NOut] {
		p.Outputs[i].DataHash, p.Outputs[i].RingDataHash = big.NewInt(0), big.NewInt(0)
	}
	p.Layout.DataFree = true
}
