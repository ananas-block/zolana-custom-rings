// Defines how enrollments sit in a ring's tracking tree, apart from its policy
// registry. Every circuit that reads an owner's enrolled key opens one of these
// leaves under the tracking root.
//
// Read after registry/registry.go. Read before registry/apply_enrollments.go,
// policy/record_pool.go, merge.go.

package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// The tree shape mirrors TRACKING_HEIGHT in program-libs/interface, enrollment is permissionless so the tree outgrows the policy registry.
const (
	TrackingHeight    = 13
	TrackingIndexBits = 2 * TrackingHeight
	TrackingCapacity  = 1 << TrackingIndexBits
)

// The empty leaf is 0, and the sentinel (0, q-1, 0, 0, 0, 0, 0, 0) at index 0 brackets every member in [1, q-2].
type TrackingRecord struct {
	Member, Next frontend.Variable
	NullifierPk  frontend.Variable
	CtHash       frontend.Variable
	// View0 and View1 are the pack_be of the owner's X25519 u.
	View0, View1 frontend.Variable
	Revision     frontend.Variable
	ListTag      frontend.Variable
}

func (r TrackingRecord) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.TrackingLeafDomain, r.Member, r.Next, r.NullifierPk, r.CtHash, r.View0, r.View1, r.Revision, r.ListTag})
}

type TrackingPath struct {
	Index    frontend.Variable
	Siblings [TrackingHeight][Arity - 1]frontend.Variable
}

func (p TrackingPath) Root(api frontend.API, leaf frontend.Variable) frontend.Variable {
	return foldQuadPath(api, p.Siblings[:], p.digits(api), leaf)
}

func (p TrackingPath) Update(api frontend.API, oldLeaf, newLeaf frontend.Variable) (oldRoot, newRoot frontend.Variable) {
	// One index decomposition places the old and the new leaf in the same slot.
	digits := p.digits(api)
	return foldQuadPath(api, p.Siblings[:], digits, oldLeaf), foldQuadPath(api, p.Siblings[:], digits, newLeaf)
}

func (p TrackingPath) digits(api frontend.API) []frontend.Variable {
	// A full tree has no index for the next leaf, a new enrollment fails here and a rotation reads an existing one.
	return api.ToBinary(p.Index, TrackingIndexBits)
}

// TrackingOpening opens one leaf, the owner's own when Present, else the low record bracketing the owner.
type TrackingOpening struct {
	Present frontend.Variable
	Record  TrackingRecord
	Path    TrackingPath
}

// TrackingRow is zero for an absent owner or an unset cond.
type TrackingRow struct {
	Present, NullifierPk, CtHash, View0, View1, Revision, ListTag frontend.Variable
}

// Resolve binds the opening to root while the boolean cond is set.
func (o TrackingOpening) Resolve(api frontend.API, cond, root, member frontend.Variable) TrackingRow {
	// 1. Present is boolean, a fraction would pass both branches below.
	api.AssertIsBoolean(o.Present)
	present := api.Mul(cond, o.Present)
	// 2. A present owner's leaf names it, an absent owner lies strictly inside the opened leaf's link.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: present, A: o.Record.Member, B: member})
	ringgadget.AssertOrderedWhen(api, api.Sub(cond, present), o.Record.Member, member, o.Record.Next)
	// 3. The leaf folds to root, a leaf of another ring's tree fails.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: o.Path.Root(api, o.Record.Hash(api)), B: root})
	return TrackingRow{
		Present:     present,
		NullifierPk: api.Mul(present, o.Record.NullifierPk),
		CtHash:      api.Mul(present, o.Record.CtHash),
		View0:       api.Mul(present, o.Record.View0),
		View1:       api.Mul(present, o.Record.View1),
		Revision:    api.Mul(present, o.Record.Revision),
		ListTag:     api.Mul(present, o.Record.ListTag),
	}
}
