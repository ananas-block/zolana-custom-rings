package privatelist_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
)

type rowCircuit struct {
	Root, Index frontend.Variable
	Subject     privatelist.Subject
	Row         privatelist.Row
	Want        [privatelist.NLists]frontend.Variable
}

func (c *rowCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	pool := privatelist.OpenPool(api, rc, 1, c.Root, []privatelist.Row{c.Row}, []privatelist.Subject{c.Subject})
	onList := pool.Read(api, privatelist.Query{Active: 1, Owner: c.Subject.Owner, Index: c.Index})
	for i := range onList {
		api.AssertIsEqual(onList[i], c.Want[i])
	}
	return nil
}

var (
	alice    = big.NewInt(0xa11ce)
	salt     = big.NewInt(0x5a17)
	noSalt   = big.NewInt(0)
	otherOne = big.NewInt(0xb0b)
)

func enrolled(t *testing.T, owner, listSalt *big.Int) privatelist.Subject {
	t.Helper()
	return privatelist.Subject{Owner: owner, Enrolled: 1, ListTag: ringprivatelist.ListTag(t, listSalt)}
}

func unenrolled(owner *big.Int) privatelist.Subject {
	return privatelist.Subject{Owner: owner, Enrolled: 0, ListTag: 0}
}

func wants(lists uint64) [privatelist.NLists]frontend.Variable {
	var want [privatelist.NLists]frontend.Variable
	for i := range want {
		want[i] = lists >> i & 1
	}
	return want
}

func rowFor(t *testing.T, tree *ringprivatelist.Tree, subject privatelist.Subject, listSalt *big.Int, lists uint64) *rowCircuit {
	t.Helper()
	return &rowCircuit{Root: tree.Root(), Index: 0, Subject: subject, Row: tree.Row(t, ringtest.AsBigInt(subject.Owner), listSalt), Want: wants(lists)}
}

func solveRow(c *rowCircuit) error {
	return test.IsSolved(&rowCircuit{}, c, ecc.BN254.ScalarField())
}

func curator(t *testing.T) *ringprivatelist.Curator {
	t.Helper()
	return &ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
}

func TestRowReadsEachCase(t *testing.T) {
	const allowed, blocked = privatelist.AllowBit, privatelist.BlockBit
	present := func(t *testing.T) privatelist.Subject { return enrolled(t, alice, salt) }
	absent := func(*testing.T) privatelist.Subject { return unenrolled(alice) }
	tests := []struct {
		name    string
		setup   func(*testing.T, *ringprivatelist.Curator)
		subject func(*testing.T) privatelist.Subject
		salt    *big.Int
		reads   uint64
	}{
		{"unenrolled owner with no curator action reads nothing", nil, absent, noSalt, 0},
		{"enrolled owner with no curator action reads nothing", nil, present, salt, 0},
		{"unenrolled listed owner reads its salt 0 block", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: noSalt, Mask: blocked, Value: blocked})
		}, absent, noSalt, blocked},
		{"enrolled listed owner reads its salted block", func(t *testing.T, c *ringprivatelist.Curator) {
			c.WriteBoth(t, alice, salt, blocked, blocked)
		}, present, salt, blocked},
		{"a block written before enrollment still reads after it, with no new write", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: noSalt, Mask: blocked, Value: blocked})
		}, present, salt, blocked},
		{"a both-position block reads under an old tracking root claiming unenrolled", func(t *testing.T, c *ringprivatelist.Curator) {
			c.WriteBoth(t, alice, salt, blocked, blocked)
		}, absent, noSalt, blocked},
		{"a salt 0 grant dies at enrollment", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: noSalt, Mask: allowed, Value: allowed})
		}, present, salt, 0},
		{"a salted grant reads for the enrolled owner", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: allowed, Value: allowed})
		}, present, salt, allowed},
		{"a salt 0 grant reads for the unenrolled owner", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: noSalt, Mask: allowed, Value: allowed})
		}, absent, noSalt, allowed},
		{"an opened leaf with the bit clear passes", func(t *testing.T, c *ringprivatelist.Curator) {
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: blocked, Value: blocked})
			c.Write(t, ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: blocked, Value: 0})
		}, present, salt, 0},
		{"another owner's entries change nothing", func(t *testing.T, c *ringprivatelist.Curator) {
			c.WriteBoth(t, otherOne, salt, blocked, blocked)
		}, present, salt, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := curator(t)
			if tt.setup != nil {
				tt.setup(t, c)
			}
			if err := solveRow(rowFor(t, c.Tree, tt.subject(t), tt.salt, tt.reads)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRowRefusals(t *testing.T) {
	const blocked = privatelist.BlockBit
	blockedTree := func(t *testing.T) *ringprivatelist.Tree {
		c := curator(t)
		c.WriteBoth(t, alice, salt, blocked, blocked)
		return c.Tree
	}
	read := []string{"privatelist.Opening.read"}
	bound := []string{"privatelist.Row.read"}
	tests := []struct {
		name   string
		build  func(*testing.T) *rowCircuit
		frames []string
	}{
		{"a listed owner claiming nonmembership is off the path", func(t *testing.T) *rowCircuit {
			c := rowFor(t, blockedTree(t), enrolled(t, alice, salt), salt, 0)
			c.Row.Salted.Written, c.Row.Salted.Lists, c.Row.Salted.LeafSalt = 0, 0, 0
			return c
		}, read},
		{"a listed owner opening its leaf with the bit clear is off the path", func(t *testing.T) *rowCircuit {
			c := rowFor(t, blockedTree(t), enrolled(t, alice, salt), salt, 0)
			c.Row.Salted.Lists = 0
			return c
		}, read},
		{"a salted clean read leaves the salt 0 block in force", func(t *testing.T) *rowCircuit {
			tree := ringprivatelist.New(t)
			tree.Apply(t, ringprivatelist.Change{Owner: alice, ListSalt: noSalt, Mask: blocked, Value: blocked}, 1)
			c := rowFor(t, tree, enrolled(t, alice, salt), salt, 0)
			c.Row.Zero.Written, c.Row.Zero.Lists, c.Row.Zero.LeafSalt = 0, 0, 0
			return c
		}, read},
		{"a wrong salt fails the final tag", func(t *testing.T) *rowCircuit {
			return rowFor(t, ringprivatelist.New(t), enrolled(t, alice, salt), big.NewInt(0x0bad), 0)
		}, bound},
		{"salt 0 for an enrolled owner fails the final tag", func(t *testing.T) *rowCircuit {
			return rowFor(t, ringprivatelist.New(t), enrolled(t, alice, salt), noSalt, 0)
		}, bound},
		{"a salt for an unenrolled owner fails", func(t *testing.T) *rowCircuit {
			return rowFor(t, ringprivatelist.New(t), unenrolled(alice), salt, 0)
		}, bound},
		{"another owner's clean opening is another position", func(t *testing.T) *rowCircuit {
			tree := blockedTree(t)
			tree.Apply(t, ringprivatelist.Change{Owner: otherOne, ListSalt: noSalt, Mask: privatelist.AllowBit, Value: 0}, 9)
			c := rowFor(t, tree, enrolled(t, alice, salt), salt, 0)
			c.Row.Salted = tree.Opening(t, otherOne, noSalt)
			return c
		}, read},
		{"a wrong tree fails the root", func(t *testing.T) *rowCircuit {
			c := rowFor(t, ringprivatelist.New(t), enrolled(t, alice, salt), salt, 0)
			c.Root = blockedTree(t).Root()
			return c
		}, read},
		{"a bitmap past the leaf width fails its split", func(t *testing.T) *rowCircuit {
			c := rowFor(t, ringprivatelist.New(t), unenrolled(alice), noSalt, 0)
			c.Row.Salted.Lists = 1 << privatelist.NLists
			return c
		}, read},
		{"a padding row serves no query", func(t *testing.T) *rowCircuit {
			c := rowFor(t, ringprivatelist.New(t), unenrolled(alice), noSalt, 0)
			c.Row.Live = 0
			return c
		}, []string{"privatelist.Pool.Read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ringtest.RequireRefused(t, solveRow(tt.build(t)), tt.frames...)
		})
	}
}

func TestRowReadsListedBitAsSet(t *testing.T) {
	c := curator(t)
	c.WriteBoth(t, alice, salt, privatelist.BlockBit, privatelist.BlockBit)
	ringtest.RequireRefused(t, solveRow(rowFor(t, c.Tree, enrolled(t, alice, salt), salt, 0)), "rowCircuit).Define")
}

func TestPoolRefusesAnotherOwner(t *testing.T) {
	c := rowFor(t, ringprivatelist.New(t), unenrolled(alice), noSalt, 0)
	ringtest.RequireRefused(t, test.IsSolved(&queryCircuit{}, &queryCircuit{rowCircuit: *c, Query: otherOne}, ecc.BN254.ScalarField()), "privatelist.Pool.Read")
}

type queryCircuit struct {
	rowCircuit
	Query frontend.Variable
}

func (c *queryCircuit) Define(api frontend.API) error {
	pool := privatelist.OpenPool(api, rangecheck.New(api), 1, c.Root, []privatelist.Row{c.Row}, []privatelist.Subject{c.Subject})
	pool.Read(api, privatelist.Query{Active: 1, Owner: c.Query, Index: c.Index})
	return nil
}

func TestInactivePoolReadsZeros(t *testing.T) {
	c := &inactiveCircuit{Root: 0x7777, Subject: unenrolled(alice), Row: ringprivatelist.PaddingRow()}
	c.Row.ListSalt = 0x123
	if err := test.IsSolved(&inactiveCircuit{}, c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

type inactiveCircuit struct {
	Root    frontend.Variable
	Subject privatelist.Subject
	Row     privatelist.Row
}

func (c *inactiveCircuit) Define(api frontend.API) error {
	pool := privatelist.OpenPool(api, rangecheck.New(api), 0, c.Root, []privatelist.Row{c.Row}, []privatelist.Subject{c.Subject})
	for _, bit := range pool.Read(api, privatelist.Query{Active: 0, Owner: 0, Index: 0}) {
		api.AssertIsEqual(bit, 0)
	}
	return nil
}

// Every empty path reaches the empty root, only the canonical split can refuse the alias.
func TestAliasedRouteIsRefused(t *testing.T) {
	q := ecc.BN254.ScalarField()
	two254 := new(big.Int).Lsh(big.NewInt(1), 254)
	owner := big.NewInt(1)
	// Only a position below 2^254-q has an alias in 254 bits.
	for new(big.Int).Add(ringprivatelist.Position(t, owner, noSalt), q).Cmp(two254) >= 0 {
		owner.Add(owner, big.NewInt(1))
	}
	position := ringprivatelist.Position(t, owner, noSalt)
	alias := new(big.Int).Add(position, q)
	aliasRoute := new(big.Int).And(alias, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), privatelist.Depth), big.NewInt(1)))
	honestRoute := new(big.Int).And(position, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), privatelist.Depth), big.NewInt(1)))
	if aliasRoute.Cmp(honestRoute) == 0 {
		t.Fatal("alias reaches the same route")
	}
	honest := rowFor(t, ringprivatelist.New(t), unenrolled(owner), noSalt, 0)
	bound := ringkey.Compile(t, &rowCircuit{})
	split := ringtest.RegisteredHint(t, "splitFieldHint")
	forged := func(_ *big.Int, in, out []*big.Int) error {
		out[0].Rsh(new(big.Int).Add(in[0], q), privatelist.Depth)
		out[1].Set(new(big.Int).And(new(big.Int).Add(in[0], q), new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), privatelist.Depth), big.NewInt(1))))
		return nil
	}
	solve := func(options ...solver.Option) error {
		witness, err := frontend.NewWitness(honest, q)
		if err != nil {
			t.Fatal(err)
		}
		return bound.IsSolved(witness, options...)
	}
	if err := solve(); err != nil {
		t.Fatal(err)
	}
	if solve(solver.OverrideHint(solver.GetHintID(split), forged)) == nil {
		t.Fatal("aliased split solved")
	}
}
