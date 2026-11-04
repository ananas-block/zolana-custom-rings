package privatelist

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Opening shows the leaf at one position, the empty leaf 0 while Written is unset.
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

// Subject is an owner and what its tracking row proves, ListTag zero while unenrolled.
type Subject struct {
	Owner    frontend.Variable
	Enrolled frontend.Variable
	ListTag  frontend.Variable
}

// Row reads one subject's list bits, Live unset marks a padding row.
type Row struct {
	Live     frontend.Variable
	ListSalt frontend.Variable
	Salted   Opening
	Zero     Opening
}

// read holds an enrolled owner to its final salt and an unenrolled one to salt 0, the caller binds Subject to the tracking root.
func (r Row) read(api frontend.API, rc frontend.Rangechecker, active, root frontend.Variable, subject Subject) [NLists]frontend.Variable {
	api.AssertIsBoolean(r.Live)
	api.AssertIsBoolean(subject.Enrolled)
	live := api.Mul(active, r.Live)
	enrolled := api.Mul(live, subject.Enrolled)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: enrolled, A: ListTag(api, r.ListSalt), B: subject.ListTag})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(live, enrolled), V: r.ListSalt})
	salted := r.Salted.read(api, rc, live, root, Position(api, subject.Owner, r.ListSalt))
	zero := r.Zero.read(api, rc, live, root, Position(api, subject.Owner, 0))
	var onList [NLists]frontend.Variable
	for i := range onList {
		onList[i] = salted[i]
		// A block written before enrollment stays readable, a salt-0 grant dies at enrollment.
		if DenyLists>>i&1 == 1 {
			onList[i] = api.Or(salted[i], zero[i])
		}
		onList[i] = api.Mul(live, onList[i])
	}
	return onList
}

// Pool serves each distinct subject's two paths once, every query is a lookup.
type Pool struct {
	active frontend.Variable
	table  *lookup.Table
}

// OpenPool reads one row per subject under root while active is set.
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

// Query asks a live row for owner, an inactive query reads zeros.
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
