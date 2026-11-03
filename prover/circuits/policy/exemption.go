// Waives the withdrawal co-signer when every withdrawn token stays within the
// threshold its record sets. The program sums the legs, the proof reads the
// threshold the record authenticates.
//
// Read after policy/subjects.go, policy/rules.go. Read before policy/screen.go.

package policy

import (
	"github.com/consensys/gnark/frontend"

	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// assertExemption holds every public slot's gross withdrawal to its asset record's threshold while exempt, a missing record reads threshold zero.
func (p *PolicyInputs) assertExemption(api frontend.API, cmp comparator, exempt frontend.Variable, assets []publicAsset) {
	for k, asset := range assets {
		// An exempt gross lies below 2^64 as the comparator needs, an unexempt gross is unbounded.
		gross := api.Mul(exempt, p.PublicGross[k])
		cmp.rc.Check(gross, transaction.AmountBits)
		cmp.rc.Check(api.Mul(exempt, asset.withdrawalThreshold), transaction.AmountBits)
		transaction.AssertWhen(api, api.Mul(exempt, asset.active), cmp.atMost(api, gross, asset.withdrawalThreshold))
	}
}
