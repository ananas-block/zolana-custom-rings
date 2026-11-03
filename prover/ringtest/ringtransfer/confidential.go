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
	Exits      []int
	AllDummies bool
	// CoOwners spend one more input each on the signer rail, each screened beside the sender.
	CoOwners []*big.Int
	// PublicFunded spends no input on the signer rail, slot 0 a dummy.
	PublicFunded  bool
	FrozenCoOwner bool
	Omitted       int
}

// Built is a confidential witness with the fixtures it was derived from.
type Built struct {
	Circuit      *transfer.ConfidentialTransferCircuit
	Audit        ringaudit.DeliveredAudit
	Own, Curator *ringregistry.Registry
	Inputs       []ringaudit.Utxo
	// Sender is the fixture sender, the signer run's first on the signer rail.
	Sender *big.Int
	World  Confidential
	// Run is the signer set the program rebuilds.
	Run []*big.Int
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
	if w.AllDummies {
		d = d.AllDummies(t)
	}
	escrow := w.Escrow || w.Rail == Delegate
	d.Layout.Escrow = escrow
	if w.Omitted > 0 {
		d = d.Omit(t, w.Omitted)
	}
	d.InputClass, d.InputCount = w.Shape.Inputs, publishedInputs+len(w.CoOwners)
	sender := Sender(t)
	inputs := make([]ringaudit.Utxo, w.Shape.Inputs)
	for i := range inputs {
		inputs[i] = ringaudit.SpareInput(i)
	}
	if !w.PublicFunded {
		// Balance sets what a sender's debit reads, half and half across its two notes.
		owed := w.owedAsset(t, d)
		nullifierPk := spptest.MustNullifierPk(t, big.NewInt(7))
		inputs[0] = ringaudit.SpentUtxo(t, sender, nullifierPk, d.RingProgramID, owed-owed/2, 51)
		inputs[1] = ringaudit.SpentUtxo(t, sender, nullifierPk, d.RingProgramID, owed/2, 52)
		for k, coOwner := range w.CoOwners {
			inputs[publishedInputs+k] = ringaudit.SpentUtxo(t, coOwner, nullifierPk, d.RingProgramID, 1, 53+int64(k))
		}
	}
	d.Inputs = inputs
	wires := d.Wires(d.Layout)
	c.FirstNullifier, c.TxViewingSk, c.EphSk, c.AuditorPk, c.Salt, c.Layout = wires.FirstNullifier, wires.TxViewingSk, wires.EphSk, wires.AuditorPk, wires.Salt, wires.Layout
	c.OutputCount = d.OutputCount()
	for i, output := range d.Outputs {
		c.Outputs[i] = output.Wires()
	}
	for i, input := range inputs {
		c.Inputs[i] = input.Wires()
	}
	c.InputCount = d.InputCount
	c.InProof, c.Delegate = bit(w.Rail == InProof), bit(w.Rail == Delegate)
	c.Exempt, c.ApprovalRequired = bit(w.Exempt), bit(w.ApprovalRequired)
	c.Sender, c.SenderPkHash = 0, 0
	switch w.Rail {
	case InProof:
		c.Sender = sender
	case Delegate:
		c.SenderPkHash = sender
	}
	var run []*big.Int
	if w.Rail == Signer {
		run = append([]*big.Int{sender}, w.CoOwners...)
	}
	c.SignerCount = len(run)
	copy(c.Signers, senderRows(w.Shape.Inputs, run...))
	c.PrivateTxBlinding = big.NewInt(privateTxBlinding)
	b := Built{Circuit: c, Audit: d, Inputs: inputs, Sender: sender, World: w, Run: run}
	senders := senderRows(len(c.SenderEntries), append([]*big.Int{sender}, w.CoOwners...)...)
	b.Own, b.Curator = policyFixture{
		Policy: w.Policy, Exempt: w.Exempt, Escrow: escrow, Published: true, Outputs: d.Utxos(), Wires: b.OutputWires(), Public: w.Public, Withdrawals: w.Withdrawals,
		Senders: senders, RingProgramID: d.RingProgramID, FrozenCoOwner: w.FrozenCoOwner,
	}.fill(t, &c.Policy)
	b.Rehash(t)
	return b
}

// owedAsset is what balance owes of the fixture asset, every output plus every net withdrawal.
func (w Confidential) owedAsset(t testing.TB, d ringaudit.DeliveredAudit) uint64 {
	t.Helper()
	owed := int64(0)
	for _, utxo := range d.Utxos() {
		if utxo.IsUtxo() && utxo.Asset.Cmp(Asset(t)) == 0 {
			owed += int64(utxo.Amount)
		}
	}
	for _, public := range w.Public {
		if public.Asset.Cmp(Asset(t)) == 0 {
			owed -= public.Net
		}
	}
	return uint64(max(owed, 0))
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
	chain := spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, b.Inputs))
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
	return b.Values(t).ConfidentialElements(t)
}

// Values is what the program holds for the statement.
func (b Built) Values(t testing.TB) Statement {
	t.Helper()
	c := b.Circuit
	s := policyStatement(&c.Policy)
	s.PrivateTxHash = ringtest.AsBigInt(c.PrivateTxHash)
	s.Head, s.Outputs, s.InputCount = b.Audit.Head(t), b.Audit.StatementOutputs(t), b.Audit.InputCount
	s.InProof, s.Delegate = ringtest.AsBigInt(c.InProof).Sign() != 0, ringtest.AsBigInt(c.Delegate).Sign() != 0
	s.Exempt, s.ApprovalRequired = ringtest.AsBigInt(c.Exempt).Sign() != 0, ringtest.AsBigInt(c.ApprovalRequired).Sign() != 0
	s.Sender = ringtest.AsBigInt(c.Sender)
	s.SignerCount, s.SignerChain = len(b.Run), ringaudit.SignerChain(t, b.Run, len(c.Signers))
	return s
}
