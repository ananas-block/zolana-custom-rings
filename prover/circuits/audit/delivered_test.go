// Pins the delivered section's refusals over bodies, exit records and the in-proof evidence.

package audit_test

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Each case changes one value of an honest transfer whose slot 0 is a ring output, slot 6 the exit and slot 7 a dummy.
func TestDeliveredAuditRefusals(t *testing.T) {
	c := compileDelivered(t, 8)
	slot := ringaudit.Recipient(t, 0, 0, 100)
	body := func(d *ringaudit.DeliveredAudit, amount uint64) [shared.BodyLen]byte {
		return ringprotocol.Body{Blinding: d.Outputs[0].Utxo.Blinding, Amount: amount, OwnerKey: slot.OwnerKey, NullifierPk: slot.NullifierPk}.Seal(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0))
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.DeliveredAudit)
	}{
		{"ring output with a data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].Utxo.DataHash = big.NewInt(5) }},
		{"exit with a ring data hash", func(d *ringaudit.DeliveredAudit) { d.Outputs[6].Utxo.RingDataHash = big.NewInt(5) }},
		{"body encrypting another amount", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Body = body(d, slot.Amount+1)
		}},
		{"ring output blinding of another slot", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Utxo.Blinding = d.Blinding(t, 1)
			d.Outputs[0].Body = body(d, slot.Amount)
		}},
		{"body naming another owner key", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Body = ringprotocol.Body{Blinding: d.Outputs[0].Utxo.Blinding, Amount: slot.Amount, OwnerKey: ringtest.Repeat(0xc3), NullifierPk: slot.NullifierPk}.Seal(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0))
		}},
		{"body naming another nullifier key", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].Body = ringprotocol.Body{Blinding: d.Outputs[0].Utxo.Blinding, Amount: slot.Amount, OwnerKey: slot.OwnerKey, NullifierPk: big.NewInt(0x1234)}.Seal(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0))
		}},
		// A body under another label would decrypt to noise for the recipient.
		{"body under the auditor stream label", func(d *ringaudit.DeliveredAudit) {
			key, nonce := ringprotocol.AuditStreamKeys(t, d.DeliveredSlotSecret(t, slot.RecipientKey, 0), shared.AuditEncInfo)
			copy(d.Outputs[0].Body[:], ringprotocol.CTREncrypt(t, key, nonce, make([]byte, shared.BodyLen)))
		}},
		// The published key would name a holder the body's slot secret never reached.
		{"wrong recipient key", func(d *ringaudit.DeliveredAudit) {
			d.Outputs[0].RecipientKey = ringaudit.Recipient(t, 1, 0, 100).RecipientKey
		}},
		{"exit blinding off the CRBS seed", func(d *ringaudit.DeliveredAudit) { d.Outputs[6].Utxo.Blinding = big.NewInt(0x5ec) }},
		{"owner key not the slot owner", func(d *ringaudit.DeliveredAudit) { d.Outputs[0].OwnerKey[0] ^= 1 }},
		{"recipient key given as its high-bit alias", func(d *ringaudit.DeliveredAudit) {
			alias := slot
			alias.RecipientKey[31] |= 0x80
			d.Outputs[0] = d.NewRingOutput(t, alias)
		}},
		{"full openings flag on a delivered key", func(d *ringaudit.DeliveredAudit) { d.Layout.FullOpenings = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ringaudit.NewDeliveredAudit(t, 8)
			tc.mutate(&d)
			c.Refuse(t, d.Circuit(t))
		})
	}

	// The program reads key escrow off the config, a body cut to the escrow length fails a statement that clears it.
	t.Run("nullifier keys omitted with the escrow bit clear", func(t *testing.T) {
		d := ringaudit.NewDeliveredAudit(t, 8)
		escrowed := d
		escrowed.Layout.Escrow = true
		c.RefuseStatement(t, d.Circuit(t), ringaudit.DeliveredStatement(t, d.Head(t), escrowed.StatementOutputs(t)))
	})
	// The exit's region is one, another slot's bytes bind another chain.
	t.Run("exit ciphertext read from another slot's region", func(t *testing.T) {
		d := ringaudit.NewDeliveredAudit(t, 8)
		outputs := d.StatementOutputs(t)
		outputs[6].Ciphertext = d.Stream(t).Record(5, audit.ExitRecordLen)
		c.RefuseStatement(t, d.Circuit(t), ringaudit.DeliveredStatement(t, d.Head(t), outputs))
	})
	// The program cuts lengths from the bitmap, the circuit derives it from the opened slots.
	t.Run("changed exit positions", func(t *testing.T) {
		d := ringaudit.NewDeliveredAudit(t, 8)
		statement := d.Statement(t)
		statement[len(statement)-1] = big.NewInt(1 << 5)
		c.RefuseStatement(t, d.Circuit(t), statement)
	})
}

// Every flag value solves at the smallest and a larger capacity, with an exit and without one.
func TestDeliveredAuditSolvesEveryLayout(t *testing.T) {
	for _, capacity := range []int{2, 8} {
		c := compileDelivered(t, capacity)
		for _, escrow := range []bool{false, true} {
			layout := ringaudit.Layout{Escrow: escrow}
			for name, build := range map[string]func(testing.TB, int) ringaudit.DeliveredAudit{
				"exit-free": func(t testing.TB, capacity int) ringaudit.DeliveredAudit {
					return ringaudit.DeliveredAuditOf(t, capacity)
				},
				"exit": ringaudit.NewDeliveredAudit,
			} {
				t.Run(fmt.Sprintf("%d/%+v/%s", capacity, layout, name), func(t *testing.T) {
					d := build(t, capacity)
					d.Layout = layout
					c.RequireSolved(t, d.Circuit(t))
				})
			}
		}
	}
}

// Bit 0 stays clear, exits_bitmap alone records exits.
func TestLayoutRefusesTheClearBits(t *testing.T) {
	c := compileDelivered(t, 8)
	for _, layout := range []int{1, 4} {
		assignment := ringaudit.NewDeliveredAudit(t, 8).Circuit(t)
		assignment.Layout = layout
		c.Refuse(t, assignment)
	}
}

// Each case changes one value of an honest in-proof owner transfer spending two sender UTXOs.
func TestDeliveredSenderAuditRefusals(t *testing.T) {
	shape := ringaudit.SenderShape{Inputs: 32, Outputs: 2}
	c := compileDeliveredSender(t, shape)
	other := ringtest.MustSolanaPkField(t, ringtest.Repeat(0xb2))
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *ringaudit.DeliveredSenderAudit, *ringaudit.DeliveredSenderCircuit)
	}{
		// The policy and the auditor would read a sender that owns no spent input.
		{"published sender other than the input owners", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *ringaudit.DeliveredSenderCircuit) {
			circuit.Sender = other
			circuit.PublicInputHash = spptest.MustHashChain4(t, ringaudit.DeliveredSenderStatement(t, d.Head(t), d.StatementOutputs(t), d.InputCount, d.PrivateTxHash(t), other))
		}},
		// SPP's hidden owner would spend a note the sender does not own.
		{"second input of another owner", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *ringaudit.DeliveredSenderCircuit) {
			circuit.Inputs[1].OwnerPkHash = other
		}},
		// The statement would name no input SPP spends.
		{"no spent UTXO", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *ringaudit.DeliveredSenderCircuit) {
			d.Inputs[0], d.Inputs[1] = d.Inputs[2], d.Inputs[3]
			*circuit = *d.Circuit(t)
		}},
		// The audited inputs would be other than the ones SPP settles.
		{"private tx hash over another blinding", func(t *testing.T, d *ringaudit.DeliveredSenderAudit, circuit *ringaudit.DeliveredSenderCircuit) {
			circuit.PrivateTxBlinding = big.NewInt(0x5b1e)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := ringaudit.NewDeliveredSenderAudit(t, shape)
			circuit := d.Circuit(t)
			tc.mutate(t, &d, circuit)
			c.Refuse(t, circuit)
		})
	}
}

// The evidence ends at the published count, a count that opens another range hashes apart.
func TestDeliveredSenderEvidenceFollowsTheInputCount(t *testing.T) {
	shape := ringaudit.SenderShape{Inputs: 32, Outputs: 2}
	c := compileDeliveredSender(t, shape)
	t.Run("a dummy below the count solves", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		d.InputCount = 3
		c.RequireSolved(t, d.Circuit(t))
	})
	// A spent note past the count stays out of the auditor's evidence.
	t.Run("a UTXO at the count", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		d.InputCount = 1
		c.Refuse(t, d.Circuit(t))
	})
	t.Run("a count past the class", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		assignment := d.Circuit(t)
		assignment.InputCount = shape.Inputs + 1
		c.Refuse(t, assignment)
	})
	// The frame's count must hold the selection, the program cuts the envelope from it.
	t.Run("a statement count over another envelope", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		statement := ringaudit.DeliveredSenderStatement(t, d.Head(t), d.StatementOutputs(t), 3, d.PrivateTxHash(t), d.Sender(t))
		c.RefuseStatement(t, d.Circuit(t), statement)
	})
	t.Run("an envelope cut at another count", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		head := d.AuditHead(t, d.Layout, d.Stream(t).Envelope(3))
		c.RefuseStatement(t, d.Circuit(t), ringaudit.DeliveredSenderStatement(t, head, d.StatementOutputs(t), 2, d.PrivateTxHash(t), d.Sender(t)))
	})
	t.Run("evidence of another note", func(t *testing.T) {
		d := ringaudit.NewDeliveredSenderAudit(t, shape)
		other := d
		other.Inputs = slices.Clone(d.Inputs)
		other.Inputs[1].Blinding = big.NewInt(53)
		head := d.AuditHead(t, d.Layout, other.Stream(t).Envelope(2))
		c.RefuseStatement(t, d.Circuit(t), ringaudit.DeliveredSenderStatement(t, head, d.StatementOutputs(t), 2, d.PrivateTxHash(t), d.Sender(t)))
	})
}
