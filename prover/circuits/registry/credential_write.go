// Binds a private owner write to its permanent credential and applied address.
// The storage program derives the credential bitmap from each write mask and
// authenticated mint preimages. A private owner write has no asset exemption.
// The public bitmap binds that classification to the write chain.
//
// The state proof fixes the owner and salt commitment. The address proof places
// the same credential identity in the checkpoint whose sequence the program
// records as its absence floor. A later accepted absence root cannot exclude
// that identity, and the owner must read its salted record.
//
// Read after registry/credential.go and shared/derivation.go.
// Read before registry/apply_records.go and policy/subjects.go.
//
// Properties
// 1. Each selected write names ListKey(Member, ListSalt) under CRPL.
// 2. CRPT binds ListSalt to the same credential that the state path opens.
// 3. State and address paths bind one ring, credential owner and address.
// 4. Unselected witnesses contain only zero values.

package registry

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

type CredentialWrite struct {
	Member, ListSalt frontend.Variable
	Leaf             CredentialLeaf
	Address          AddressLeaf
}

func (w CredentialWrite) Assert(api frontend.API, active, member, addressRoot frontend.Variable, roots CredentialRoots) {
	api.AssertIsBoolean(active)
	// 1. CRPL binds the write key and CRPT binds its salt to the opened credential.
	assertCredentialEqualWhen(api, active, w.Leaf.Member, w.Member)
	assertCredentialEqualWhen(api, active, shared.ListKey(api, w.Member, w.ListSalt), member)
	assertCredentialEqualWhen(api, active, shared.ListTag(api, w.ListSalt), w.Leaf.ListTag)
	api.ToBinary(w.ListSalt, 248)
	assertCredentialEqualWhen(api, active, api.IsZero(w.ListSalt), 0)
	// 2. Both proofs name the same derived address under the statement's ring and owner.
	address := w.Leaf.AssertInclusion(api, active, roots)
	w.Address.AssertInclusion(api, active, address, addressRoot)
	// 3. Unselected writes carry no private owner or salt.
	inactive := api.Sub(1, active)
	for _, value := range []frontend.Variable{w.Member, w.ListSalt, w.Leaf.Member} {
		assertCredentialEqualWhen(api, inactive, value, 0)
	}
}

func (c *ApplyRecordsCircuit) credentialBits(api frontend.API) []frontend.Variable {
	bits := api.ToBinary(c.CredentialWrites, c.NumWrites)
	present := api.Sub(1, api.IsZero(c.CredentialWrites))
	// A usable checkpoint has a private ring, while an empty read has one zero encoding.
	assertCredentialEqualWhen(api, present, api.IsZero(c.PrivateRingID), 0)
	assertCredentialEqualWhen(api, present, api.IsZero(c.CredentialOwner), 0)
	assertCredentialEqualWhen(api, present, api.IsZero(c.AddressRoot), 0)
	inactive := api.Sub(1, present)
	for _, value := range []frontend.Variable{c.PrivateRingID, c.CredentialOwner, c.AddressRoot} {
		assertCredentialEqualWhen(api, inactive, value, 0)
	}
	for _, root := range c.StateRoots {
		for _, value := range root {
			assertCredentialEqualWhen(api, inactive, value, 0)
		}
	}
	return bits
}
