package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func TestScalarOwnerGuardAcrossInactivePayments(t *testing.T) {
	for _, different := range []bool{false, true} {
		for _, withdrawal := range []bool{false, true} {
			for _, firstLive := range []bool{false, true} {
				w := ringpolicy.Confidential()
				w.Outputs = 4
				w.Table.Limits = nil
				w.Table.Rules[0].Guard = policy.GuardAboveAmount
				w.Table.Rules[0].Threshold = 1000
				w.Slots = []ringpolicy.Slot{{}, {Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 100}, {}, {Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 100}}
				if firstLive {
					w.Slots[0], w.Slots[1] = w.Slots[1], w.Slots[0]
				}
				last := &w.Slots[3]
				if withdrawal {
					w.WithdrawalCapacity = 2
					w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
					last = &w.Withdrawals[0]
				}
				if different {
					last.Asset = ringpolicy.AssetB
				}
				b := w.Build(t)
				err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField())
				if (err != nil) != different {
					t.Fatalf("different=%v withdrawal=%v firstLive=%v error=%v", different, withdrawal, firstLive, err)
				}
			}
		}
	}
}

func TestWithdrawalPrefixZeroPadding(t *testing.T) {
	for _, capacity := range policy.WithdrawalCapacities {
		for _, count := range []int{0, max(0, capacity-1), capacity} {
			w := ringpolicy.Confidential()
			w.OwnOnly, w.WithdrawalCapacity = true, capacity
			w.Table.Limits = nil
			for range count {
				w.Withdrawals = append(w.Withdrawals, ringpolicy.Slot{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 1})
			}
			b := w.Build(t)
			if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("capacity=%d count=%d error=%v", capacity, count, err)
			}
			if count < capacity {
				b.Member.Withdrawals[count].Asset = ringpolicy.AssetB
				if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
					t.Fatalf("nonzero suffix passed at capacity=%d count=%d", capacity, count)
				}
			}
		}
	}
}
