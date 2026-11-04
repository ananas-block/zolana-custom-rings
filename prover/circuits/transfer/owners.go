package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// OwnerRows are the key's S rows, the policy and the input predicate read them and no prover input orders them.
type OwnerRows struct {
	Members  []frontend.Variable
	Live     []frontend.Variable
	Tracking []policy.TrackingView
}

// OpenOwnerRows holds live rows strictly ascending with zero rows last, a repeated owner would split its debit across rows.
func OpenOwnerRows(api frontend.API, members, entries []frontend.Variable, pool policy.TrackingPool) OwnerRows {
	rows := OwnerRows{Members: members, Live: make([]frontend.Variable, len(members)), Tracking: make([]policy.TrackingView, len(members))}
	for j, member := range members {
		rows.Live[j] = ringgadget.IsNonZero(api, member)
		if j > 0 {
			ringgadget.AssertOrderedWhen(api, rows.Live[j], 0, members[j-1], member)
		}
		rows.Tracking[j] = pool.Row(api, rows.Live[j], member, entries[j])
	}
	return rows
}

// find is set on the one live row of owner, with that row's enrolled key, a zero owner matches no padding.
func (r OwnerRows) find(api frontend.API, owner frontend.Variable) (found, key frontend.Variable) {
	found, key = 0, 0
	for j, member := range r.Members {
		hit := api.Mul(r.Live[j], api.IsZero(api.Sub(owner, member)))
		found = api.Add(found, hit)
		key = api.Add(key, api.Mul(hit, r.Tracking[j].NullifierPk))
	}
	return found, key
}

// InputRail is what the input predicate reads about the rail.
type InputRail struct {
	// Delegate moves a zero-key note with no row, no policy reads the rows there.
	Delegate frontend.Variable
	// Hidden is set while HiddenOwner spends privately.
	Hidden, HiddenOwner frontend.Variable
}

// AssertInputOwners holds every live input to its row and enrolled key, an input past the rows would skip the sender rules and the auditor's nullifier.
func (r OwnerRows) AssertInputOwners(api frontend.API, rail InputRail, inputs []shared.Output) {
	for _, slot := range inputs {
		zeroKey := isZeroKey(api, slot.NullifierPk)
		found, key := r.find(api, slot.OwnerPkHash)
		needsRow := api.Mul(slot.Utxo, api.Sub(1, api.Mul(rail.Delegate, zeroKey)))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: needsRow, V: api.Sub(1, found)})
		// A default-ring note carries a key the ring never enrolled.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(slot.Ring, api.Sub(1, zeroKey)), A: slot.NullifierPk, B: key})
		// Anyone holding the opening computes a zero-key nullifier, that spend would name the hidden owner.
		hidden := api.Mul(rail.Hidden, slot.Utxo, zeroKey)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(api.Sub(slot.OwnerPkHash, rail.HiddenOwner))})
	}
}

// AssertOutputOwners holds a live ring output to its owner's enrolled key, and a zero key to an owner with no row under the root.
func AssertOutputOwners(api frontend.API, pool policy.TrackingPool, outputs []shared.Output, entries []frontend.Variable) {
	for o, slot := range outputs {
		row := pool.Row(api, slot.Ring, slot.OwnerPkHash, entries[o])
		zeroKey := isZeroKey(api, slot.NullifierPk)
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: row.NullifierPk, B: api.Mul(api.Sub(1, zeroKey), slot.NullifierPk)})
		// A literal zero key would read as an absent row, and nobody could spend it.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Ring, V: api.IsZero(slot.NullifierPk)})
	}
}

func isZeroKey(api frontend.API, nullifierPk frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(nullifierPk, shared.ZeroNullifierPk))
}
