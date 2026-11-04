package privatelist

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// ApplyWidths mirrors PRIVATE_LIST_APPLY_WIDTHS in program-libs/interface/src/accounts/private_list.rs.
var ApplyWidths = []int{2, 8, 16}

// The program reads only the chained position, new leaf and counter.
type Write struct {
	Member       frontend.Variable
	ListSalt     frontend.Variable
	WriteCounter frontend.Variable
	Mask         frontend.Variable
	Value        frontend.Variable
	OldWritten   frontend.Variable
	OldLists     frontend.Variable
	OldLeafSalt  frontend.Variable
	Siblings     [Depth]frontend.Variable
}

type ApplyCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot    frontend.Variable
	NewRoot    frontend.Variable
	ChainStart frontend.Variable
	ChainEnd   frontend.Variable
	Count      frontend.Variable
	Writes     []Write
}

func NewApplyCircuit(writes int) (*ApplyCircuit, error) {
	if err := shared.ValidateWidth("private list", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyCircuit{NumWrites: writes, Writes: make([]Write, writes)}, nil
}

type applyState struct {
	root, chain, restricts frontend.Variable
}

func (c *ApplyCircuit) Define(api frontend.API) error {
	if err := errors.Join(shared.ValidateWidth("private list", c.NumWrites, ApplyWidths), shared.ValidateLength("private list", "write", len(c.Writes), c.NumWrites)); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	state := applyState{root: c.OldRoot, chain: c.ChainStart, restricts: 0}
	for i, write := range c.Writes {
		state = write.apply(api, rc, count.Active[i], state)
	}
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	// The sum stays far below q, zero exactly when no active write restricts.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(ringgadget.IsNonZero(api, state.restricts))))
	return nil
}

func (w Write) apply(api frontend.API, rc frontend.Rangechecker, active frontend.Variable, s applyState) applyState {
	mask, value := api.ToBinary(w.Mask, NLists), api.ToBinary(w.Value, NLists)
	old := api.ToBinary(w.OldLists, NLists)
	lists := frontend.Variable(0)
	restricts := frontend.Variable(0)
	for i := range mask {
		if WritableLists>>i&1 == 0 {
			api.AssertIsEqual(mask[i], 0)
		}
		api.AssertIsEqual(api.Mul(value[i], api.Sub(1, mask[i])), 0)
		lists = api.Add(lists, api.Mul(api.Add(api.Mul(old[i], api.Sub(1, mask[i])), value[i]), new(big.Int).Lsh(big.NewInt(1), uint(i))))
		// Clearing a grant or setting a deny narrows who passes, an older root must then stop serving.
		switch {
		case GrantLists>>i&1 == 1:
			restricts = api.Add(restricts, api.Sub(mask[i], value[i]))
		case DenyLists>>i&1 == 1:
			restricts = api.Add(restricts, value[i])
		}
	}
	api.AssertIsBoolean(w.OldWritten)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, w.OldWritten), V: w.OldLists})
	position := Position(api, w.Member, w.ListSalt)
	route := Route(api, rc, position)
	oldLeaf := api.Mul(w.OldWritten, Leaf(api, position, w.OldLists, w.OldLeafSalt))
	// The same salt derives position and leaf salt, a written leaf opens for the owner's salt holder.
	newLeaf := Leaf(api, position, lists, LeafSalt(api, w.ListSalt, w.WriteCounter))
	opened := pathRoot(api, oldLeaf, route, w.Siblings)
	written := pathRoot(api, newLeaf, route, w.Siblings)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: active, A: opened, B: s.root})
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, EntryHash(api, position, newLeaf, w.WriteCounter)})
	return applyState{
		root:      api.Select(active, written, s.root),
		chain:     api.Select(active, chain, s.chain),
		restricts: api.Add(s.restricts, api.Mul(active, restricts)),
	}
}

// EntryHash mirrors PublishedListWrite::entry_hash in program-libs/interface/src/accounts/private_list.rs.
func EntryHash(api frontend.API, position, leaf, writeCounter frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{shared.ListWriteDomain, position, leaf, writeCounter})
}

// statement mirrors ApplyPrivateListStatement::elements in program-libs/interface/src/accounts/private_list.rs.
func (c *ApplyCircuit) statement(restrictive frontend.Variable) []frontend.Variable {
	return []frontend.Variable{shared.ApplyListDomain, c.OldRoot, c.NewRoot, c.ChainStart, c.ChainEnd, c.Count, restrictive}
}
