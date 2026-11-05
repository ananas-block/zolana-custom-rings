// Proves permanent audit credentials under SPP state roots and reads their
// addresses in the fixed address namespace. Enroll alone signs for the credential
// owner and creates its immutable output after RegisterKey verification. State
// inclusion therefore inherits that verification, including the sealed key and salt.
// The program must derive the credential owner and authenticate every supplied root.
//
// A positive read needs only state inclusion. A private write also proves address
// inclusion and raises the absence floor atomically. An address gap under a root
// above that floor permits a salted off-list answer. It does not prove that no
// credential is settled, because a settled address can remain queued.
//
// Read after registry/register_key.go and the SPP transaction hash gadgets.
// Read before registry/credential_write.go, policy/credentials.go and merge.go.
//
// Properties
// 1. CRCR binds the credential fields in the same order as the CRRG seal statement.
// 2. CRCA fixes one address from the ring, member and program-derived owner in tree zero.
// 3. UNIQ binds the address and state hash inside the SPP data output.
// 4. State inclusion binds the selected tree id and deterministic enrollment blinding.
// 5. Address gaps use strict canonical field ordering and authenticate their low leaf.
// 6. Inactive paths and payloads are zero, while an absent pool entry keeps its member.

package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	spp "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const uniqueDataHashDomain = 0x554e4951

type Credential struct {
	RingID, Member, NullifierPk, ListTag frontend.Variable
	Aud, Eph                             [2]frontend.Variable
	CtHash                               frontend.Variable
}

type CredentialRoots struct {
	RingID, Owner frontend.Variable
	StateRoots    [][2]frontend.Variable
}

type CredentialLeaf struct {
	Credential
	Blinding, TreeSlot, StateIndex frontend.Variable
	StatePath                      [spp.StateTreeHeight]frontend.Variable
}

type AddressLeaf struct {
	Next, Index frontend.Variable
	Path        [spp.NullifierTreeHeight]frontend.Variable
}

type AddressGap struct {
	Low, Next, Index frontend.Variable
	Path             [spp.NullifierTreeHeight]frontend.Variable
}

func (c Credential) Elements(domain frontend.Variable) []frontend.Variable {
	return []frontend.Variable{domain, c.RingID, c.Member, c.NullifierPk, c.ListTag, c.Aud[0], c.Aud[1], c.Eph[0], c.Eph[1], c.CtHash}
}

func (c Credential) StateHash(api frontend.API) frontend.Variable {
	return gadget.HashChain4(api, c.Elements(shared.CredentialStateDomain))
}

func (c Credential) DataHash(api frontend.API, address frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{uniqueDataHashDomain, address, c.StateHash(api)})
}

func (c Credential) UtxoHash(api frontend.API, credentialOwner, treeID, blinding frontend.Variable) frontend.Variable {
	address := CredentialAddress(api, credentialOwner, c.RingID, c.Member)
	return c.utxoHash(api, credentialOwner, treeID, blinding, address)
}

func CredentialAddress(api frontend.API, credentialOwner, ringID, member frontend.Variable) frontend.Variable {
	seed := gadget.PoseidonHash(api, []frontend.Variable{shared.CredentialSeedDomain, ringID, member})
	addressUtxo := spp.UtxoHashCircuit(api, spp.UtxoCircuitFields{
		Domain: spp.AddressDomain, Owner: credentialOwner, Asset: 0, Amount: 0,
		Blinding: seed, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
	}, 0)
	return abstractor.Call(api, spp.NullifierGadget{UtxoHash: addressUtxo, Blinding: seed, NullifierSecret: 0})
}

func (c CredentialLeaf) AssertInclusion(api frontend.API, active frontend.Variable, roots CredentialRoots) frontend.Variable {
	// 1. The statement ring and owner derive the same address as the sole Enroll output.
	api.AssertIsBoolean(active)
	address := CredentialAddress(api, roots.Owner, roots.RingID, c.Member)
	// 2. Enroll writes one credential with the address as first nullifier and the SPP account seed.
	seed := spp.DeriveOutputBlindingSeed(api, address, 1)
	blinding := spp.DeriveOutputBlinding(api, address, seed, 0)
	assertCredentialEqualWhen(api, active, c.RingID, roots.RingID)
	assertCredentialEqualWhen(api, active, c.Blinding, blinding)
	assertCredentialEqualWhen(api, active, api.IsZero(c.Member), 0)
	assertCredentialEqualWhen(api, active, api.IsZero(c.NullifierPk), 0)
	assertCredentialEqualWhen(api, active, api.IsZero(api.Sub(c.NullifierPk, shared.ZeroNullifierPk)), 0)
	// 3. An absent entry keeps only Member, and cannot expose unproved credential columns.
	inactive := api.Sub(1, active)
	for _, value := range []frontend.Variable{c.RingID, c.NullifierPk, c.ListTag, c.Aud[0], c.Aud[1], c.Eph[0], c.Eph[1], c.CtHash, c.Blinding, c.TreeSlot} {
		assertCredentialEqualWhen(api, inactive, value, 0)
	}
	// 4. The selected root authenticates the same tree id that enters the SPP leaf hash.
	treeID, root := roots.selectState(api, c.TreeSlot)
	leaf := c.utxoHash(api, roots.Owner, treeID, c.Blinding, address)
	assertCredentialPath(api, active, leaf, root, c.StateIndex, c.StatePath[:])
	return address
}

func (g AddressGap) AssertAbsent(api frontend.API, active, address, root frontend.Variable) {
	// 1. The bound address root authenticates the low leaf and its successor.
	api.AssertIsBoolean(active)
	inactive := api.Sub(1, active)
	assertCredentialEqualWhen(api, inactive, g.Low, 0)
	assertCredentialEqualWhen(api, inactive, g.Next, 0)
	leaf := gadget.IndexedLeafHash(api, g.Low, g.Next)
	assertCredentialPath(api, active, leaf, root, g.Index, g.Path[:])
	// 2. Strict canonical ordering excludes every address already present at that checkpoint.
	abstractor.CallVoid(api, spp.AssertStrictlyOrdered{
		Lo: api.Mul(active, g.Low), Mid: api.Select(active, address, 1), Hi: api.Select(active, g.Next, 2),
	})
}

// Private writes use address inclusion before the program raises the absence floor.
func (l AddressLeaf) AssertInclusion(api frontend.API, active, address, root frontend.Variable) {
	api.AssertIsBoolean(active)
	assertCredentialEqualWhen(api, api.Sub(1, active), l.Next, 0)
	leaf := gadget.IndexedLeafHash(api, address, l.Next)
	assertCredentialPath(api, active, leaf, root, l.Index, l.Path[:])
}

func (c Credential) utxoHash(api frontend.API, credentialOwner, treeID, blinding, address frontend.Variable) frontend.Variable {
	return spp.UtxoHashCircuit(api, spp.UtxoCircuitFields{
		Domain: spp.UtxoDomain, Owner: credentialOwner, Asset: shared.SolAssetField, Amount: 0,
		Blinding: blinding, DataHash: c.DataHash(api, address), RingDataHash: 0, RingProgramID: 0,
	}, treeID)
}

func (r CredentialRoots) selectState(api frontend.API, index frontend.Variable) (frontend.Variable, frontend.Variable) {
	treeIDs := make([]frontend.Variable, len(r.StateRoots))
	roots := make([]frontend.Variable, len(r.StateRoots))
	for i, root := range r.StateRoots {
		api.ToBinary(root[0], 16)
		treeIDs[i], roots[i] = root[0], root[1]
	}
	return selector.Mux(api, index, treeIDs...), selector.Mux(api, index, roots...)
}

func assertCredentialPath(api frontend.API, active, leaf, root, index frontend.Variable, path []frontend.Variable) {
	inactive := api.Sub(1, active)
	assertCredentialEqualWhen(api, inactive, index, 0)
	for _, sibling := range path {
		assertCredentialEqualWhen(api, inactive, sibling, 0)
	}
	// Index decomposition covers the whole path and rejects an alias outside the tree capacity.
	computed := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: leaf, Index: api.ToBinary(index, len(path)), Path: path, Height: len(path),
	})
	assertCredentialEqualWhen(api, active, computed, root)
}

func assertCredentialEqualWhen(api frontend.API, active, value, expected frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: value, B: expected})
}
