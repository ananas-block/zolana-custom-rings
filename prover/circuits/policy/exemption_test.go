package policy_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

// exemptWorld withdraws gross of AssetA to Bob under a record threshold of 100.
func exemptWorld(gross uint64) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Exempt, w.WithdrawalCapacity = true, 2
	w.Own[ringpolicy.AssetA] = ringpolicy.Record{WithdrawalThreshold: 100}
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: gross}}
	w.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: -int64(gross), Gross: gross}}
	return w
}

func TestExemptionBoundsEveryPublicSlot(t *testing.T) {
	requireSolved(t, exemptWorld(100).Build(t))
	t.Run("gross above the threshold", func(t *testing.T) {
		b := exemptWorld(101).Build(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), "policy.(*PolicyInputs).assertExemption")
	})
	t.Run("asset without a record", func(t *testing.T) {
		w := exemptWorld(100)
		w.Withdrawals[0].Asset, w.Public[0].Asset = ringpolicy.AssetB, ringpolicy.AssetB
		b := w.Build(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), "policy.(*PolicyInputs).assertExemption")
	})
	t.Run("gross past u64", func(t *testing.T) {
		b := exemptWorld(100).Build(t)
		b.Policy().PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		b.Rebind(t)
		if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
			t.Fatal("an exempt gross past u64 solved")
		}
	})
	t.Run("unexempt gross past u64 stays unread", func(t *testing.T) {
		w := exemptWorld(100)
		w.Exempt = false
		b := w.Build(t)
		b.Policy().PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		b.Rebind(t)
		requireSolved(t, b)
	})
	t.Run("audit-only ring reads the record", func(t *testing.T) {
		w := exemptWorld(100)
		w.Unscreened = true
		requireSolved(t, w.Build(t))
		w = exemptWorld(101)
		w.Unscreened = true
		b := w.Build(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), "policy.(*PolicyInputs).assertExemption")
	})
}
