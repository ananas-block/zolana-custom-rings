package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type Rail int

const (
	Signer Rail = iota
	InProof
	Delegate
)

// Confidential is one transfer of the confidential family, Build derives every hash from it.
type Confidential struct {
	Shape  transfer.ConfidentialShape
	Rail   Rail
	Policy Policy
	Exempt bool
	// Escrow is the layout's key escrow flag, forced on the authority rail.
	Escrow           bool
	ApprovalRequired bool
	Public           []PublicSlot
	Withdrawals      []Withdrawal
	// Exits are the audit's exit slots, by default the second to last slot of a key past two outputs.
	Exits []int
}

// Built is a confidential witness with the fixtures it was derived from.
type Built struct {
	Circuit      *transfer.ConfidentialTransferCircuit
	Audit        ringaudit.DeliveredAudit
	Own, Curator *ringregistry.Registry
	Inputs       []ringaudit.Utxo
	// Sender is the screened identity, the statement's on the signer and in-proof rails.
	Sender *big.Int
	World  Confidential
}

// Signed is a policy ring transfer on the signer rail of shape.
func Signed(shape transfer.ConfidentialShape) Confidential {
	return Confidential{Shape: shape, Rail: Signer, Policy: Policy{Screened: true, Cap: 1_000_000, CosignAbove: 500_000, Threshold: 100}}
}

func (w Confidential) Build(t testing.TB) Built {
	t.Helper()
	c, err := transfer.NewConfidentialTransferCircuit(w.Shape)
	if err != nil {
		t.Fatal(err)
	}
	exits := w.Exits
	if exits == nil && w.Shape.Outputs > 2 {
		exits = []int{w.Shape.Outputs - 2}
	}
	d := ringaudit.DeliveredAuditOf(t, w.Shape.Outputs, exits...)
	escrow := w.Escrow || w.Rail == Delegate
	d.Layout.Escrow = escrow
	sender := Sender(t)
	inputs := make([]ringaudit.Utxo, w.Shape.Inputs)
	for i := range inputs {
		inputs[i] = ringaudit.SpareInput(i)
	}
	if w.Rail != Signer {
		nullifierPk := spptest.MustNullifierPk(t, big.NewInt(7))
		inputs[0] = ringaudit.SpentUtxo(t, sender, nullifierPk, d.RingProgramID, 100, 51)
		inputs[1] = ringaudit.SpentUtxo(t, sender, nullifierPk, d.RingProgramID, 60, 52)
	}
	wires := d.Wires(d.Layout)
	c.FirstNullifier, c.TxViewingSk, c.EphSk, c.AuditorPk, c.Salt, c.Layout = wires.FirstNullifier, wires.TxViewingSk, wires.EphSk, wires.AuditorPk, wires.Salt, wires.Layout
	for i, output := range d.Outputs {
		c.Outputs[i] = output.Wires()
	}
	for i, input := range inputs {
		c.Inputs[i] = input.Wires()
	}
	c.InProof, c.Delegate = bit(w.Rail == InProof), bit(w.Rail == Delegate)
	c.Exempt, c.ApprovalRequired = bit(w.Exempt), bit(w.ApprovalRequired)
	c.Sender, c.SenderPkHash = sender, sender
	if w.Rail == Delegate {
		c.Sender = 0
	}
	c.InputChain = big.NewInt(inputChain)
	c.PrivateTxBlinding = big.NewInt(privateTxBlinding)
	b := Built{Circuit: c, Audit: d, Inputs: inputs, Sender: sender, World: w}
	b.Own, b.Curator = fillPolicy(t, &c.Policy, w.Policy, w.Exempt, escrow, d.Utxos(), b.OutputWires(), w.Public, w.Withdrawals, sender, true, d.RingProgramID)
	b.Rehash(t)
	return b
}

// OutputWires are the slot wires the audit and the policy share.
func (b Built) OutputWires() []shared.UtxoWires {
	wires := make([]shared.UtxoWires, len(b.Circuit.Outputs))
	for o, output := range b.Circuit.Outputs {
		wires[o] = output.Output
	}
	return wires
}

// Rehash recomputes private_tx_hash from the fixture slots and inputs, then the public input.
func (b Built) Rehash(t testing.TB) {
	t.Helper()
	c := b.Circuit
	chain := ringtest.AsBigInt(c.InputChain)
	if b.World.Rail != Signer {
		chain = spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, b.Inputs))
	}
	outputs := spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, b.Audit.Utxos()))
	c.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{chain, outputs, big.NewInt(0), ringtest.AsBigInt(c.PrivateTxBlinding)})
	b.Rebind(t)
}

// Rebind recomputes the public input after a statement value changes.
func (b Built) Rebind(t testing.TB) {
	t.Helper()
	b.Circuit.WithdrawalHash = withdrawalHash(t, &b.Circuit.Policy)
	b.Circuit.PublicInputHash = spptest.MustHashChain4(t, b.Statement(t))
}

func (b Built) Statement(t testing.TB) []*big.Int {
	t.Helper()
	c := b.Circuit
	s := policyStatement(&c.Policy)
	s.PrivateTxHash = ringtest.AsBigInt(c.PrivateTxHash)
	s.Head, s.Outputs, s.Disclosure = b.Audit.AuditHead(t, b.Audit.Layout), b.Audit.StatementOutputs(t), b.Audit.Disclosure(t)
	s.InProof, s.Delegate = ringtest.AsBigInt(c.InProof).Sign() != 0, ringtest.AsBigInt(c.Delegate).Sign() != 0
	s.Exempt, s.ApprovalRequired = ringtest.AsBigInt(c.Exempt).Sign() != 0, ringtest.AsBigInt(c.ApprovalRequired).Sign() != 0
	s.Sender = ringtest.AsBigInt(c.Sender)
	return s.ConfidentialElements(t)
}
