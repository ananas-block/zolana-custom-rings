package policy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
)

var _ [NSources]frontend.Variable = [privatelist.NLists]frontend.Variable{}

// The decoded rules read an owner row through the private source and an asset row through its public column.
type privateRowsCircuit struct {
	Root       frontend.Variable
	Source     privatelist.Source
	Subject    privatelist.Subject
	Row        privatelist.Row
	OwnerRule  frontend.Variable
	AssetRule  frontend.Variable
	OwnerLists [NSources]frontend.Variable
	AssetLists [NSources]frontend.Variable
}

func (c *privateRowsCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	view := c.Source.View(api)
	pool := privatelist.OpenPool(api, rc, view.Any, c.Root, []privatelist.Row{c.Row}, []privatelist.Subject{c.Subject})
	private := pool.Read(api, privatelist.Query{Active: view.Any, Owner: c.Subject.Owner, Index: 0})
	api.AssertIsEqual(decodeRule(api, rc, c.OwnerRule).refuses(api, view.OwnerRow(api, c.OwnerLists, private)), 0)
	api.AssertIsEqual(decodeRule(api, rc, c.AssetRule).refuses(api, c.AssetLists), 0)
	return nil
}

func packedRule(subject, mode, mask uint64) *big.Int {
	return new(big.Int).SetUint64(subject | mode<<8 | mask<<16)
}

func listWires(lists uint64) [NSources]frontend.Variable {
	var wires [NSources]frontend.Variable
	for i := range wires {
		wires[i] = lists >> i & 1
	}
	return wires
}

func TestRulesReadPrivateOwnerRowsBesideAPublicAssetSource(t *testing.T) {
	const allow, block = privatelist.AllowBit, privatelist.BlockBit
	owner, salt := big.NewInt(0xa11ce), big.NewInt(0x5a17)
	assetAllow := packedRule(SubjectAsset, ModePresent, allow)
	present := packedRule(SubjectOutputOwner, ModePresent, allow)
	absent := packedRule(SubjectOutputOwner, ModeAbsent, block)
	tests := []struct {
		name       string
		privateOn  uint64
		rule       *big.Int
		write      *ringprivatelist.Change
		public     uint64
		assetLists uint64
		refused    bool
	}{
		{"absent rule passes with no curator action", block, absent, nil, 0, allow, false},
		{"absent rule refuses a private listed owner", block, absent, &ringprivatelist.Change{Mask: block, Value: block}, 0, allow, true},
		{"absent rule passes an opened leaf with the bit clear", block, absent, &ringprivatelist.Change{Mask: allow, Value: allow}, 0, allow, false},
		{"present rule passes a private granted owner", allow, present, &ringprivatelist.Change{Mask: allow, Value: allow}, 0, allow, false},
		{"present rule refuses an owner with no private grant", allow, present, nil, 0, allow, true},
		{"a public bit does not stand in for a private slot", allow, present, nil, allow, allow, true},
		{"a public slot beside a private one keeps its public read", block, present, nil, allow, allow, false},
		{"a public block beside a private slot reads private", allow, absent, nil, block, allow, true},
		{"an asset on its public list passes with the same slot private for owners", allow, absent, nil, 0, allow, false},
		{"an asset off its public list refuses with the same slot private for owners", allow, absent, nil, 0, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tree := ringprivatelist.New(t)
			if tt.write != nil {
				tt.write.Owner, tt.write.ListSalt = owner, salt
				tree.Apply(t, *tt.write, 1)
			}
			c := &privateRowsCircuit{
				Root:       tree.Root(),
				Source:     privatelist.Source{OwnerLists: tt.privateOn, Registry: 1},
				Subject:    privatelist.Subject{Owner: owner, Enrolled: 1, ListTag: ringprivatelist.ListTag(t, salt)},
				Row:        tree.Row(t, owner, salt),
				OwnerRule:  tt.rule,
				AssetRule:  assetAllow,
				OwnerLists: listWires(tt.public),
				AssetLists: listWires(tt.assetLists),
			}
			err := test.IsSolved(&privateRowsCircuit{}, c, ecc.BN254.ScalarField())
			if tt.refused {
				ringtest.RequireRefused(t, err, "privateRowsCircuit).Define")
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// A Present rule reads only the salted position once the tracking row exists.
func TestAllowlistedWalletRefusedAfterEnrollingUntilTheSaltedWrite(t *testing.T) {
	const allow = privatelist.AllowBit
	owner, salt := big.NewInt(0xa11ce), big.NewInt(0x5a17)
	curator := ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
	curator.WriteUnenrolled(t, owner, allow, allow)
	solve := func(subject privatelist.Subject, listSalt *big.Int) error {
		c := &privateRowsCircuit{
			Root:       curator.Tree.Root(),
			Source:     privatelist.Source{OwnerLists: allow, Registry: 1},
			Subject:    subject,
			Row:        curator.Tree.Row(t, owner, listSalt),
			OwnerRule:  packedRule(SubjectOutputOwner, ModePresent, allow),
			AssetRule:  packedRule(SubjectAsset, ModePresent, allow),
			OwnerLists: listWires(0),
			AssetLists: listWires(allow),
		}
		return test.IsSolved(&privateRowsCircuit{}, c, ecc.BN254.ScalarField())
	}
	tag := ringprivatelist.ListTag(t, salt)
	if err := solve(privatelist.Subject{Owner: owner, Enrolled: 0, ListTag: 0}, big.NewInt(0)); err != nil {
		t.Fatalf("unenrolled %v", err)
	}
	ringtest.RequireRefused(t, solve(privatelist.Subject{Owner: owner, Enrolled: 1, ListTag: tag}, salt), "privateRowsCircuit).Define")
	curator.WriteSalted(t, owner, salt, tag, allow, allow)
	if err := solve(privatelist.Subject{Owner: owner, Enrolled: 1, ListTag: tag}, salt); err != nil {
		t.Fatalf("after the salted write %v", err)
	}
}
