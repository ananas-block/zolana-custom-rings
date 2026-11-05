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
// 7. A pool opening folds one 40 level path. Present stops at the state root at level 32, absent reaches the address root.

package registry

import (
	"slices"

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

// CheckedRoots is the only table an opening reads, every tree id in it is range checked once.
type CheckedRoots struct {
	table CredentialRoots
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

// CredentialOpening reads one pool member, present under a state root or absent under the address root.
type CredentialOpening struct {
	Present frontend.Variable
	Leaf    CredentialLeaf
	Gap     AddressGap
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

func (c CredentialLeaf) AssertInclusion(api frontend.API, active frontend.Variable, roots CheckedRoots) frontend.Variable {
	address, leaf, root := c.bind(api, active, roots)
	assertCredentialPath(api, active, leaf, root, c.StateIndex, c.StatePath[:])
	return address
}

// Open authenticates a present credential at state height or an absent address at address height through one fold.
func (o CredentialOpening) Open(api frontend.API, active frontend.Variable, roots CheckedRoots, addressRoot frontend.Variable) {
	// 1. A live slot is present or absent, and padding selects neither branch.
	api.AssertIsBoolean(active)
	api.AssertIsBoolean(o.Present)
	api.AssertIsEqual(api.Mul(api.Sub(1, active), o.Present), 0)
	absent := api.Sub(active, o.Present)
	// 2. Each branch proves its own leaf and zeroes its own path when unselected.
	address, stateLeaf, stateRoot := o.Leaf.bind(api, o.Present, roots)
	gapLeaf := o.Gap.orderedLeaf(api, absent, address)
	assertPathZeroWhen(api, api.Sub(1, o.Present), o.Leaf.StateIndex, o.Leaf.StatePath[:])
	assertPathZeroWhen(api, api.Sub(1, absent), o.Gap.Index, o.Gap.Path[:])
	// 3. Step 2 zeroes the unselected path, so a linear sum gives the selected index and siblings at no constraint cost.
	index := api.Add(o.Leaf.StateIndex, o.Gap.Index)
	path := slices.Clone(o.Gap.Path[:])
	for level, sibling := range o.Leaf.StatePath {
		path[level] = api.Add(path[level], sibling)
	}
	// 4. One decomposition bounds an absent index by the address tree and a present index by the state tree.
	bits := api.ToBinary(index, spp.NullifierTreeHeight)
	for _, bit := range bits[spp.StateTreeHeight:] {
		assertCredentialEqualWhen(api, o.Present, bit, 0)
	}
	// 5. The state root sits at state height on the fold and the address root at its top.
	// Present selects leaf, height and root together, so a state leaf never meets the address root
	// and a gap leaf never meets a state root.
	leaf := api.Select(o.Present, stateLeaf, gapLeaf)
	stateNode := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: leaf, Index: bits[:spp.StateTreeHeight], Path: path[:spp.StateTreeHeight], Height: spp.StateTreeHeight,
	})
	addressNode := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: stateNode, Index: bits[spp.StateTreeHeight:], Path: path[spp.StateTreeHeight:],
		Height: spp.NullifierTreeHeight - spp.StateTreeHeight,
	})
	computed := api.Select(o.Present, stateNode, addressNode)
	assertCredentialEqualWhen(api, active, computed, api.Select(o.Present, stateRoot, addressRoot))
}

// bind proves the credential columns and returns its address, SPP leaf and selected state root.
func (c CredentialLeaf) bind(api frontend.API, active frontend.Variable, roots CheckedRoots) (address, leaf, root frontend.Variable) {
	// 1. The statement ring and owner derive the same address as the sole Enroll output.
	api.AssertIsBoolean(active)
	address = CredentialAddress(api, roots.table.Owner, roots.table.RingID, c.Member)
	// 2. Enroll writes one credential with the address as first nullifier and the SPP account seed.
	seed := spp.DeriveOutputBlindingSeed(api, address, 1)
	blinding := spp.DeriveOutputBlinding(api, address, seed, 0)
	assertCredentialEqualWhen(api, active, c.RingID, roots.table.RingID)
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
	return address, c.utxoHash(api, roots.table.Owner, treeID, c.Blinding, address), root
}

// orderedLeaf zeroes an inactive gap and orders an active one, the caller authenticates the returned leaf.
func (g AddressGap) orderedLeaf(api frontend.API, active, address frontend.Variable) frontend.Variable {
	api.AssertIsBoolean(active)
	inactive := api.Sub(1, active)
	assertCredentialEqualWhen(api, inactive, g.Low, 0)
	assertCredentialEqualWhen(api, inactive, g.Next, 0)
	// Strict canonical ordering excludes every address already present at the checkpoint.
	abstractor.CallVoid(api, spp.AssertStrictlyOrdered{
		Lo: api.Mul(active, g.Low), Mid: api.Select(active, address, 1), Hi: api.Select(active, g.Next, 2),
	})
	return gadget.IndexedLeafHash(api, g.Low, g.Next)
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

// Check range checks each tree id once, every opening then binds to one checked entry by index.
func (r CredentialRoots) Check(api frontend.API) CheckedRoots {
	for _, root := range r.StateRoots {
		api.ToBinary(root[0], 16)
	}
	return CheckedRoots{table: r}
}

// selectState's mux refuses an index outside the table, the tree id and the root come from one entry.
func (r CheckedRoots) selectState(api frontend.API, index frontend.Variable) (frontend.Variable, frontend.Variable) {
	treeIDs := make([]frontend.Variable, len(r.table.StateRoots))
	roots := make([]frontend.Variable, len(r.table.StateRoots))
	for i, root := range r.table.StateRoots {
		treeIDs[i], roots[i] = root[0], root[1]
	}
	return selector.Mux(api, index, treeIDs...), selector.Mux(api, index, roots...)
}

func assertCredentialPath(api frontend.API, active, leaf, root, index frontend.Variable, path []frontend.Variable) {
	assertPathZeroWhen(api, api.Sub(1, active), index, path)
	// Index decomposition covers the whole path and rejects an alias outside the tree capacity.
	computed := abstractor.Call(api, gadget.MerkleRootGadget{
		Hash: leaf, Index: api.ToBinary(index, len(path)), Path: path, Height: len(path),
	})
	assertCredentialEqualWhen(api, active, computed, root)
}

func assertPathZeroWhen(api frontend.API, inactive, index frontend.Variable, path []frontend.Variable) {
	assertCredentialEqualWhen(api, inactive, index, 0)
	for _, sibling := range path {
		assertCredentialEqualWhen(api, inactive, sibling, 0)
	}
}

func assertCredentialEqualWhen(api frontend.API, active, value, expected frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: value, B: expected})
}
