// Package privatelist proves owner lists whose entries stay private, a sparse Merkle tree keyed by a salted position.
package privatelist

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const (
	// Depth mirrors PRIVATE_LIST_DEPTH in program-libs/interface/src/accounts/private_list.rs.
	Depth = 96
	// NLists is the leaf bitmap width, small enough for a salt holder to open a leaf by trial.
	NLists = 8
)

// List bits mirror ListId in program-libs/policy/src/list.rs, bit i is list i+1.
const (
	AllowBit    = 1 << 0
	BlockBit    = 1 << 1
	FrozenBit   = 1 << 2
	ReaderBit   = 1 << 5
	ApprovalBit = 1 << 6

	GrantLists = AllowBit | ApprovalBit
	DenyLists  = BlockBit | FrozenBit
	// WritableLists mirrors ListSet::AUTHORITY_WRITES.
	WritableLists = GrantLists | DenyLists | ReaderBit
)

// ListSalt is one way, a disclosed salt reveals no nullifier secret.
func ListSalt(api frontend.API, nullifierSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListSaltDomain, nullifierSecret})
}

func ListTag(api frontend.API, listSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListTagDomain, listSalt})
}

func Position(api frontend.API, owner, listSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListPositionDomain, owner, listSalt})
}

func LeafSalt(api frontend.API, listSalt, writeCounter frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListLeafSaltDomain, listSalt, writeCounter})
}

// Leaf binds the whole position, a leaf of another position sharing the route never opens.
func Leaf(api frontend.API, position, lists, leafSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListLeafDomain, position, lists, leafSalt})
}

// Route is the low Depth bits of the canonical position, position+q would reach another leaf.
func Route(api frontend.API, rc frontend.Rangechecker, position frontend.Variable) []frontend.Variable {
	_, low := ringgadget.SplitField(api, rc, position, Depth)
	return api.ToBinary(low, Depth)
}

func pathRoot(api frontend.API, leaf frontend.Variable, route []frontend.Variable, siblings [Depth]frontend.Variable) frontend.Variable {
	return abstractor.Call(api, gadget.MerkleRootGadget{Hash: leaf, Index: route, Path: siblings[:], Height: Depth})
}
