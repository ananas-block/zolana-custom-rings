package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// The in-proof owner takes no run address, so eleven co-owners, eight recipients and thirty two
// unenrolled withdrawal owners beside it name 52 distinct subjects under a salted list.
func TestTheWidestInProofSpendOpensEveryCredential(t *testing.T) {
	w := onRail(wideOwners2, ringtransfer.InProof)
	w.SaltedBlock, w.Exits = []*big.Int{}, []int{}
	for k := range 11 {
		w.CoOwners = append(w.CoOwners, big.NewInt(0x1000+int64(k)))
	}
	asset := ringtransfer.Asset(t)
	for leg := range 32 {
		w.Withdrawals = append(w.Withdrawals, ringtransfer.Withdrawal{Owner: big.NewInt(0x2000 + int64(leg)), Asset: asset, Amount: 1})
	}
	w.Public = []ringtransfer.PublicSlot{{Asset: asset, Net: -32, Gross: 32}}
	w.Outputs = map[int]func(*ringaudit.Slot){}
	for slot := range wideOwners2.Outputs {
		w.Outputs[slot] = func(output *ringaudit.Slot) {
			output.OwnerKey = ringtest.Repeat(0xd0 + byte(slot))
			output.Utxo.OwnerPkHash = ringtest.MustSolanaPkField(t, output.OwnerKey)
			output.Utxo.NullifierPk = spptest.MustNullifierPk(t, big.NewInt(0x300+int64(slot)))
		}
	}
	built := w.Build(t)
	live := 0
	for _, opening := range built.Circuit.Openings {
		if ringtest.AsBigInt(opening.Leaf.Member).Sign() != 0 {
			live++
		}
	}
	if live != 52 || len(built.Circuit.Openings) != 52 {
		t.Fatalf("%d live openings in a pool of %d, want 52 in 52", live, len(built.Circuit.Openings))
	}
	requireSolved(t, built.Circuit)
	// A dropped opening leaves its subject's read unanswered.
	built.Circuit.Openings[len(built.Circuit.Openings)-1] = policy.CredentialOpening(ringregistry.ZeroCredentialOpening())
	refused(t, built.Circuit)
}
