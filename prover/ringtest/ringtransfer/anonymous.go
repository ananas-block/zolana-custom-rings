package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Anonymous is one transfer of the anonymous family, Build derives every hash from it.
type Anonymous struct {
	Shape            transfer.AnonymousShape
	Policy           Policy
	Exempt           bool
	ApprovalRequired bool
	Public           []PublicSlot
	Withdrawals      []Withdrawal
	AllDummies       bool
}

// BuiltAnonymous is an anonymous witness with the fixtures it was derived from.
type BuiltAnonymous struct {
	Circuit      *transfer.AnonymousTransferCircuit
	Audit        ringaudit.AnonymousAudit
	Own, Curator *ringregistry.Registry
	World        Anonymous
}

// Hidden is a policy ring transfer of shape on the anonymous rail.
func Hidden(shape transfer.AnonymousShape) Anonymous {
	return Anonymous{Shape: shape, Policy: Policy{Screened: true, Cap: 1_000_000, CosignAbove: 500_000, Threshold: 100}}
}

func (w Anonymous) Build(t testing.TB) BuiltAnonymous {
	t.Helper()
	c, err := transfer.NewAnonymousTransferCircuit(w.Shape)
	if err != nil {
		t.Fatal(err)
	}
	a := ringaudit.NewAnonymousAudit(t, audit.AnonymousAuditShape{InputClass: w.Shape.InputClass, Outputs: w.Shape.Outputs, FullOpenings: w.Shape.FullOpenings})
	if w.AllDummies {
		a = a.AllDummies(t)
	}
	wires := a.Wires(a.Layout)
	c.FirstNullifier, c.TxViewingSk, c.EphSk, c.AuditorPk, c.Salt, c.Layout = wires.FirstNullifier, wires.TxViewingSk, wires.EphSk, wires.AuditorPk, wires.Salt, wires.Layout
	for i, output := range a.Outputs {
		c.Outputs[i] = audit.AnonymousOutputWires{Output: output.Utxo.Wires()}
		ringtest.SetBytes(c.Outputs[i].OwnerKey[:], output.OwnerKey[:])
	}
	if w.Shape.FullOpenings {
		ringtest.SetBytes(c.SenderKey, a.SenderKey[:])
	}
	c.InputCount = a.InputCount
	for i, input := range a.Inputs {
		c.Inputs[i] = input.Wires()
	}
	for i, party := range a.PartyIdentities {
		c.PartyIdentities[i] = party
	}
	c.Exempt, c.ApprovalRequired = bit(w.Exempt), bit(w.ApprovalRequired)
	b := BuiltAnonymous{Circuit: c, Audit: a, World: w}
	sender := a.SenderPkHash(t)
	b.Own, b.Curator = fillPolicy(t, &c.Policy, w.Policy, w.Exempt, false, a.Utxos(), b.OutputWires(), w.Public, w.Withdrawals, sender, false, a.RingProgramID)
	c.PrivateTxBlinding = a.PrivateTxBlinding
	c.PrivateTxHash = a.PrivateTxHash(t)
	b.Rebind(t)
	return b
}

// OutputWires are the slot wires the audit and the policy share.
func (b BuiltAnonymous) OutputWires() []shared.UtxoWires {
	wires := make([]shared.UtxoWires, len(b.Circuit.Outputs))
	for o, output := range b.Circuit.Outputs {
		wires[o] = output.Output
	}
	return wires
}

// Rebind recomputes the public input after a statement value changes.
func (b BuiltAnonymous) Rebind(t testing.TB) {
	t.Helper()
	b.Circuit.WithdrawalHash = withdrawalHash(t, &b.Circuit.Policy)
	b.Circuit.PublicInputHash = spptest.MustHashChain4(t, b.Statement(t))
}

func (b BuiltAnonymous) Statement(t testing.TB) []*big.Int {
	t.Helper()
	c := b.Circuit
	s := policyStatement(&c.Policy)
	s.PrivateTxHash = ringtest.AsBigInt(c.PrivateTxHash)
	stream := b.Audit.Stream(t)
	s.Head, s.Outputs, s.InputCount = b.Audit.AuditHead(t, b.Audit.Layout, stream.Envelope(b.Audit.InputCount)), b.Audit.StatementOutputs(t, stream), b.Audit.InputCount
	s.Exempt, s.ApprovalRequired = ringtest.AsBigInt(c.Exempt).Sign() != 0, ringtest.AsBigInt(c.ApprovalRequired).Sign() != 0
	for i, party := range c.PartyIdentities {
		s.PartyIdentities[i] = ringtest.AsBigInt(party)
	}
	return s.AnonymousElements(t)
}
