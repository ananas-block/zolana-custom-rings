package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type Rail int

const (
	Signer Rail = iota
	InProof
	Delegate
)

// Confidential is one transfer of the confidential family.
type Confidential struct {
	World
	Shape transfer.ConfidentialShape
	Rail  Rail
}

// Built is a confidential witness with the fixtures it was derived from.
type Built struct {
	Assembled
	Circuit *transfer.ConfidentialTransferCircuit
	World   Confidential
}

// Signed is a policy ring transfer on the signer rail of shape.
func Signed(shape transfer.ConfidentialShape) Confidential {
	return Confidential{Shape: shape, Rail: Signer, World: World{Policy: Policy{Screened: true, Cap: 1_000_000, CosignAbove: 500_000, WithdrawalThreshold: 100_000}}}
}

func (w Confidential) Build(t testing.TB) Built {
	t.Helper()
	c, err := transfer.NewConfidentialTransferCircuit(w.Shape)
	if err != nil {
		t.Fatal(err)
	}
	a := w.newAudit(t, audit.StreamShape{InputClass: w.Shape.Inputs, Outputs: w.Shape.Outputs, Entry: w.Shape.Entry, Data: w.Shape.Data})
	sender := Sender(t)
	var run []*big.Int
	switch w.Rail {
	case Signer:
		run = append([]*big.Int{sender}, w.CoOwners...)
	case InProof:
		run = w.CoOwners
	}
	c.InProof, c.Delegate, c.Sender = ringtest.Bit(w.Rail == InProof), ringtest.Bit(w.Rail == Delegate), 0
	if w.Rail == InProof {
		c.Sender = sender
	}
	b := Built{Circuit: c, World: w, Assembled: w.fill(t, &c.Sections, a, w.Rail == Delegate, run)}
	b.Rehash(t)
	return b
}

// Rehash recomputes private_tx_hash from the fixture slots and inputs, then the public input.
func (b Built) Rehash(t testing.TB) {
	t.Helper()
	rehash(t, &b.Circuit.Sections, b.Audit)
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
	return b.Values(t).Elements(t)
}

// Values is what the program holds for the statement.
func (b Built) Values(t testing.TB) Statement {
	t.Helper()
	c := b.Circuit
	s := values(t, &c.Sections, b.Assembled)
	s.RailBits = [2]bool{ringtest.AsBigInt(c.InProof).Sign() != 0, ringtest.AsBigInt(c.Delegate).Sign() != 0}
	s.Cells = []*big.Int{ringtest.AsBigInt(c.Sender)}
	return s
}
