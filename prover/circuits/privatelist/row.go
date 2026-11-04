package privatelist

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Opens the empty leaf 0 while Written is unset.
type Opening struct {
	Written  frontend.Variable
	Lists    frontend.Variable
	LeafSalt frontend.Variable
	Siblings [Depth]frontend.Variable
}

// read yields no list bit from an unwritten position.
func (o Opening) read(api frontend.API, rc frontend.Rangechecker, enabled, root, position frontend.Variable) [NLists]frontend.Variable {
	api.AssertIsBoolean(o.Written)
	leaf := api.Mul(o.Written, Leaf(api, position, o.Lists, o.LeafSalt))
	opened := pathRoot(api, leaf, Route(api, rc, position), o.Siblings)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: enabled, A: opened, B: root})
	var onList [NLists]frontend.Variable
	for i, bit := range api.ToBinary(o.Lists, NLists) {
		onList[i] = api.Mul(o.Written, bit)
	}
	return onList
}

// ListTag counts only while Enrolled is set.
type Subject struct {
	Owner    frontend.Variable
	Enrolled frontend.Variable
	ListTag  frontend.Variable
}

// Live unset marks a padding row.
type Row struct {
	Live     frontend.Variable
	ListSalt frontend.Variable
	Salted   Opening
	Zero     Opening
}

// The caller must bind Subject to the tracking root, an unbound Subject picks its salt.
func (r Row) read(api frontend.API, rc frontend.Rangechecker, active, root frontend.Variable, subject Subject) [NLists]frontend.Variable {
	api.AssertIsBoolean(r.Live)
	api.AssertIsBoolean(subject.Enrolled)
	live := api.Mul(active, r.Live)
	enrolled := api.Mul(live, subject.Enrolled)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: enrolled, A: shared.ListTag(api, r.ListSalt), B: subject.ListTag})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(live, enrolled), V: r.ListSalt})
	salted := r.Salted.read(api, rc, live, root, Position(api, subject.Owner, r.ListSalt))
	zero := r.Zero.read(api, rc, live, root, Position(api, subject.Owner, 0))
	var onList [NLists]frontend.Variable
	for i := range onList {
		onList[i] = salted[i]
		// A deny written before enrollment stays readable, a salt 0 grant dies at enrollment.
		if DenyLists>>i&1 == 1 {
			onList[i] = api.Or(salted[i], zero[i])
		}
		onList[i] = api.Mul(live, onList[i])
	}
	return onList
}

type Pool struct {
	active frontend.Variable
	table  *lookup.Table
}

func OpenPool(api frontend.API, rc frontend.Rangechecker, active, root frontend.Variable, rows []Row, subjects []Subject) Pool {
	if len(rows) != len(subjects) {
		panic("private list pool needs one subject per row")
	}
	api.AssertIsBoolean(active)
	pool := Pool{active: active, table: lookup.New(api, 2+NLists)}
	for i, row := range rows {
		onList := row.read(api, rc, active, root, subjects[i])
		pool.table.Insert(append([]frontend.Variable{subjects[i].Owner, row.Live}, onList[:]...))
	}
	return pool
}

type Query struct {
	Active, Owner, Index frontend.Variable
}

func (p Pool) Read(api frontend.API, query Query) [NLists]frontend.Variable {
	api.AssertIsBoolean(query.Active)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: query.Active, V: api.Sub(1, p.active)})
	row := p.table.Lookup(query.Index)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: query.Active, A: row[0], B: query.Owner})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: query.Active, V: api.Sub(1, row[1])})
	var onList [NLists]frontend.Variable
	for i := range onList {
		onList[i] = api.Mul(query.Active, row[2+i])
	}
	return onList
}
