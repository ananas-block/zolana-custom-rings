package shared

import "github.com/consensys/gnark/frontend"

// AssertAnonymousParties separates the hidden owner from the public identities
// reconstructed by the verifier. Zero denotes an absent optional party.
func AssertAnonymousParties(api frontend.API, owner frontend.Variable, parties [3]frontend.Variable) {
	for _, party := range parties {
		api.AssertIsEqual(api.Mul(party, api.IsZero(api.Sub(owner, party))), 0)
	}
}
