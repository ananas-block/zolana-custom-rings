package registry

import (
	"errors"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// TrackingEntry mirrors the entry the program computes from an authorization account.
type TrackingEntry struct {
	Member, NullifierPk, CtHash, View0, View1, Revision, ListTag frontend.Variable
}

func (e TrackingEntry) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.TrackingEntryDomain, e.Member, e.NullifierPk, e.CtHash, e.View0, e.View1, e.Revision, e.ListTag})
}

// EnrollmentWrite's Slot opens the owner's leaf, or the empty leaf an insert takes.
type EnrollmentWrite struct {
	Entry   TrackingEntry
	Exists  frontend.Variable
	Old     TrackingRecord
	Slot    TrackingPath
	Low     TrackingRecord
	LowSlot TrackingPath
}

// ApplyEnrollmentsCircuit only moves the tree, the program computes each entry and anyone may apply.
type ApplyEnrollmentsCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot      frontend.Variable
	NewRoot      frontend.Variable
	OldNextIndex frontend.Variable
	NewNextIndex frontend.Variable
	ChainStart   frontend.Variable
	ChainEnd     frontend.Variable
	Count        frontend.Variable
	Writes       []EnrollmentWrite
}

func NewApplyEnrollmentsCircuit(writes int) (*ApplyEnrollmentsCircuit, error) {
	if err := shared.ValidateWidth("tracking", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyEnrollmentsCircuit{NumWrites: writes, Writes: make([]EnrollmentWrite, writes)}, nil
}

func (c *ApplyEnrollmentsCircuit) Define(api frontend.API) error {
	if err := errors.Join(shared.ValidateWidth("tracking", c.NumWrites, ApplyWidths), shared.ValidateLength("tracking", "write", len(c.Writes), c.NumWrites)); err != nil {
		return err
	}
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	// 2. Every active write moves the running root, next index and chain in the named order.
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart}
	for i, w := range c.Writes {
		state = w.apply(api, count.Active[i], state)
	}
	// 3. The tree after the batch and the entries it consumed are the statement's.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement()))
	return nil
}

func (w EnrollmentWrite) apply(api frontend.API, active frontend.Variable, s registryState) registryState {
	api.AssertIsBoolean(w.Exists)
	rotates := api.Mul(active, w.Exists)
	inserts := api.Sub(active, rotates)
	// 1. A rotation opens the owner's own leaf and keeps its final fields.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: rotates, A: w.Old.Member, B: w.Entry.Member})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: rotates, A: w.Old.NullifierPk, B: w.Entry.NullifierPk})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: rotates, A: w.Old.CtHash, B: w.Entry.CtHash})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: rotates, A: w.Old.ListTag, B: w.Entry.ListTag})
	// 2. An absent owner lies strictly inside its low record's link under the running root, a link no present owner falls inside.
	ringgadget.AssertOrderedWhen(api, inserts, w.Low.Member, w.Entry.Member, w.Low.Next)
	relinked := w.Low
	relinked.Next = w.Entry.Member
	lowRoot, relinkedRoot := w.LowSlot.Update(api, w.Low.Hash(api), relinked.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inserts, A: lowRoot, B: s.root})
	linked := api.Select(inserts, relinkedRoot, s.root)
	// 3. An insert takes the empty leaf at the next index, linking on to the low record's old next.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inserts, A: w.Slot.Index, B: s.next})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: inserts, A: w.Old.Next, B: w.Low.Next})
	// 4. The entry replaces the slot's old leaf under the linked root, an insert's old leaf is the empty leaf 0.
	before := api.Select(w.Exists, w.Old.Hash(api), 0)
	after := TrackingRecord{
		Member: w.Entry.Member, Next: w.Old.Next, NullifierPk: w.Entry.NullifierPk, CtHash: w.Entry.CtHash,
		View0: w.Entry.View0, View1: w.Entry.View1, Revision: w.Entry.Revision, ListTag: w.Entry.ListTag,
	}.Hash(api)
	opened, written := w.Slot.Update(api, before, after)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: opened, B: linked})
	// 5. The chain absorbs every active entry, the program computed each from its account.
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, w.Entry.Hash(api)})
	return registryState{
		root:  api.Select(active, written, s.root),
		next:  api.Add(s.next, inserts),
		chain: api.Select(active, chain, s.chain),
	}
}

// statement mirrors ApplyEnrollmentsStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *ApplyEnrollmentsCircuit) statement() []frontend.Variable {
	return []frontend.Variable{
		shared.ApplyEnrollmentsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
	}
}
