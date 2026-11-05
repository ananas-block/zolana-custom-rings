// Binds each ring note's nullifier key for a nonzero secret to its owner's permanent audit credential.
// The sender rows also give the policy every input note owner it must screen.
//
// SPP accepts any output nullifier key. The ring auditor can derive a spent note's nullifier only
// from a secret sealed during enrollment or the public zero secret. A nonzero secret therefore needs
// a credential with the same key. ZeroNullifierPk remains auditable without a credential, even for
// an enrolled owner, but its later spend reveals that owner. The hidden rail refuses such inputs.
//
// Read after transfer/input.go, policy/credentials.go, registry/register_key.go. Read before
// policy/screen.go, policy/outflow.go.
//
// Properties established for the transfer statement.
// 1. Every input note owner has a live row, the delegate's zero-key note alone goes without.
// 2. A ring input key outside ZeroNullifierPk equals its row's key from authenticated credential state.
// 3. A hidden owner spends no zero-key note, its public nullifier would name the owner.
// 4. A ring output key outside ZeroNullifierPk equals its owner's credential key, and literal zero fails.
// 5. A zero-key output needs no credential for its key check, applicable salted rules still authenticate its owner.
//
// A zero-key note stays spendable after enrollment. Its sender row remains authenticated even when
// no salted rule applies, and the policy requires the same owner's fixed salt when such a rule applies.

package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// OwnerRows are the key's S rows, the policy and the input predicate read them and a constraint orders them.
type OwnerRows struct {
	Members     []frontend.Variable
	Live        []frontend.Variable
	Credentials []policy.CredentialView
}

// InputRail is what the input predicate reads about the rail.
type InputRail struct {
	// Delegate moves a zero-key note with no row, no policy reads the rows there.
	Delegate frontend.Variable
	// Hidden is set while HiddenOwner spends privately.
	Hidden, HiddenOwner frontend.Variable
}

// OpenOwnerRows authenticates each live row, the policy holds the rows in order off the authority rail.
func OpenOwnerRows(api frontend.API, members, entries []frontend.Variable, pool policy.CredentialPool) OwnerRows {
	rows := OwnerRows{Members: members, Live: make([]frontend.Variable, len(members)), Credentials: make([]policy.CredentialView, len(members))}
	for j, member := range members {
		rows.Live[j] = ringgadget.IsNonZero(api, member)
		rows.Credentials[j] = pool.Row(api, rows.Live[j], member, entries[j])
	}
	return rows
}

// AssertInputOwners binds each input note to its owner row and key, the sender rules and auditor depend on the same opening.
func (r OwnerRows) AssertInputOwners(api frontend.API, rail InputRail, inputs []shared.Output) {
	for _, slot := range inputs {
		zeroKey := isZeroKey(api, slot.NullifierPk)
		found, key := r.find(api, slot.OwnerPkHash)
		// 1. Every input note has its owner's row, the sender rules and attribution read rows alone.
		// Only the delegate's zero-key note goes without. Exactly one match also refuses duplicate rows on the authority rail.
		needsRow := api.Mul(slot.Utxo, api.Sub(1, api.Mul(rail.Delegate, zeroKey)))
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: needsRow, V: api.Sub(1, found)})
		// 2. A ring note's key is the row's enrolled key, the auditor reads the nullifier through it. A default-ring note carries a key the ring never enrolled.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: api.Mul(slot.Ring, api.Sub(1, zeroKey)), A: slot.NullifierPk, B: key})
		// 3. Anyone holding the opening computes a zero-key nullifier, that spend would name the hidden owner.
		hidden := api.Mul(rail.Hidden, slot.Utxo, zeroKey)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: policy.IsSame(api, slot.OwnerPkHash, rail.HiddenOwner)})
	}
}

// find is set on the one live row of owner, with that row's enrolled key, a zero owner matches no padding.
func (r OwnerRows) find(api frontend.API, owner frontend.Variable) (found, key frontend.Variable) {
	found, key = 0, 0
	for j, member := range r.Members {
		hit := api.Mul(r.Live[j], policy.IsSame(api, owner, member))
		found = api.Add(found, hit)
		key = api.Add(key, api.Mul(hit, r.Credentials[j].NullifierPk))
	}
	return found, key
}

// AssertOutputOwners binds a ring output key outside ZeroNullifierPk to its owner's permanent credential.
// ZeroNullifierPk remains auditable without a credential, the policy independently enforces any salted payee read.
func AssertOutputOwners(api frontend.API, pool policy.CredentialPool, outputs []shared.Output, entries []frontend.Variable) {
	for o, slot := range outputs {
		// 1. A nonzero secret needs the credential that sealed it to the auditor. Default-ring outputs
		// and zero-key outputs require no credential for the key check.
		zeroKey := isZeroKey(api, slot.NullifierPk)
		needsCredential := api.Mul(slot.Ring, api.Sub(1, zeroKey))
		row := pool.Row(api, needsCredential, slot.OwnerPkHash, entries[o])
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: needsCredential, A: row.NullifierPk, B: slot.NullifierPk})
		// 2. Literal zero is no usable nullifier key, and must not match the absent credential result.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Ring, V: api.IsZero(slot.NullifierPk)})
	}
}

func isZeroKey(api frontend.API, nullifierPk frontend.Variable) frontend.Variable {
	return policy.IsSame(api, nullifierPk, shared.ZeroNullifierPk)
}
