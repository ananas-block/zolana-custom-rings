package privatelist_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const chainSeed = 0x5eed

func applyCircuit(t testing.TB, writes int) *privatelist.ApplyCircuit {
	t.Helper()
	c, err := privatelist.NewApplyCircuit(writes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// applied assigns the batch as an honest curator proves it, the host statement is the program's.
func applied(t testing.TB, tree *ringprivatelist.Tree, width int, restrictive bool, writes []ringprivatelist.Applied, oldRoot *big.Int) *privatelist.ApplyCircuit {
	t.Helper()
	c := applyCircuit(t, width)
	chain := big.NewInt(chainSeed)
	for i := range c.Writes {
		c.Writes[i] = ringprivatelist.ZeroWrite()
	}
	for i, write := range writes {
		c.Writes[i] = write.Wires
		chain = ringtest.MustPoseidonHash(t, chain, write.Published.EntryHash(t))
	}
	c.OldRoot, c.NewRoot, c.ChainStart, c.ChainEnd, c.Count = oldRoot, tree.Root(), big.NewInt(chainSeed), chain, len(writes)
	bindStatement(t, c, restrictive)
	return c
}

func statementOf(c *privatelist.ApplyCircuit, restrictive bool) []*big.Int {
	statement := []*big.Int{big.NewInt(shared.ApplyListDomain)}
	for _, v := range []frontend.Variable{c.OldRoot, c.NewRoot, c.ChainStart, c.ChainEnd, c.Count} {
		statement = append(statement, ringtest.AsBigInt(v))
	}
	return append(statement, big.NewInt(ringtest.Bit(restrictive)))
}

func bindStatement(t testing.TB, c *privatelist.ApplyCircuit, restrictive bool) {
	t.Helper()
	c.PublicInputHash = spptest.MustHashChain4(t, statementOf(c, restrictive))
}

func honestBatch(t testing.TB, width int, restrictive bool, changes ...ringprivatelist.Change) (*ringprivatelist.Tree, *privatelist.ApplyCircuit) {
	t.Helper()
	curator := ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
	oldRoot := curator.Tree.Root()
	writes := make([]ringprivatelist.Applied, len(changes))
	for i, change := range changes {
		writes[i] = curator.Tree.Apply(t, change, uint64(i+1))
	}
	return curator.Tree, applied(t, curator.Tree, width, restrictive, writes, oldRoot)
}

func setBlock(owner *big.Int) ringprivatelist.Change {
	return ringprivatelist.Change{Owner: owner, ListSalt: salt, Mask: privatelist.BlockBit, Value: privatelist.BlockBit}
}

// A batch writes a salted position and another owner's salt 0 position, a later batch edits a written leaf.
func TestApplyWritesEachPositionKindThenEditsALeaf(t *testing.T) {
	curator := ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
	tag := ringprivatelist.ListTag(t, salt)
	oldRoot := curator.Tree.Root()
	batch := []ringprivatelist.Applied{
		curator.WriteSalted(t, alice, salt, tag, privatelist.BlockBit, privatelist.BlockBit),
		curator.WriteUnenrolled(t, otherOne, privatelist.BlockBit, privatelist.BlockBit),
	}
	first := applied(t, curator.Tree, 2, true, batch, oldRoot)
	bound := ringkey.Bind(t, applyCircuit(t, 2), first)
	bound.RequireSolved(t, first)
	secondRoot := curator.Tree.Root()
	// The second edit keeps the bit the first edit of the batch set.
	edits := []ringprivatelist.Applied{
		curator.WriteSalted(t, alice, salt, tag, privatelist.AllowBit, privatelist.AllowBit),
		curator.WriteSalted(t, alice, salt, tag, privatelist.BlockBit, 0),
	}
	bound.RequireSolved(t, applied(t, curator.Tree, 2, false, edits, secondRoot))
	opened := curator.Tree.Read(t, alice, salt)
	if !opened.Written || opened.Lists != privatelist.AllowBit {
		t.Fatalf("lists %b", opened.Lists)
	}
}

func TestApplyRestrictiveBit(t *testing.T) {
	const (
		allow    = privatelist.AllowBit
		block    = privatelist.BlockBit
		frozen   = privatelist.FrozenBit
		reader   = privatelist.ReaderBit
		approval = privatelist.ApprovalBit
	)
	tests := []struct {
		name        string
		changes     [][2]uint64
		restrictive bool
	}{
		{"setting a grant list is permissive", [][2]uint64{{allow, allow}}, false},
		{"setting approval is permissive", [][2]uint64{{approval, approval}}, false},
		{"clearing a deny list is permissive", [][2]uint64{{block, 0}}, false},
		{"clearing frozen is permissive", [][2]uint64{{frozen, 0}}, false},
		{"setting a deny list is restrictive", [][2]uint64{{block, block}}, true},
		{"setting frozen is restrictive", [][2]uint64{{frozen, frozen}}, true},
		{"clearing a grant list is restrictive", [][2]uint64{{allow, 0}}, true},
		{"clearing approval is restrictive", [][2]uint64{{approval, 0}}, true},
		{"a reader write is neutral", [][2]uint64{{reader, reader}}, false},
		{"clearing reader is neutral", [][2]uint64{{reader, 0}}, false},
		{"an empty mask is neutral", [][2]uint64{{0, 0}}, false},
		{"one restricting bit in a permissive write restricts", [][2]uint64{{allow | block, allow | block}}, true},
		{"one restricting write in a batch restricts", [][2]uint64{{allow, allow}, {block, block}}, true},
		{"a permissive batch stays permissive", [][2]uint64{{allow, allow}, {block, 0}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changes := make([]ringprivatelist.Change, len(tt.changes))
			for i, change := range tt.changes {
				changes[i] = ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: change[0], Value: change[1]}
			}
			_, honest := honestBatch(t, 2, tt.restrictive, changes...)
			bound := ringkey.Bind(t, applyCircuit(t, 2), honest)
			// The program's statement under the opposite bit fails at the binding alone.
			bound.RefuseStatement(t, honest, statementOf(honest, !tt.restrictive))
		})
	}
}

// Padding past the count cannot raise the bit.
func TestApplyPaddingNeverRestricts(t *testing.T) {
	_, honest := honestBatch(t, 2, false, ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: privatelist.AllowBit, Value: privatelist.AllowBit})
	bound := ringkey.Bind(t, applyCircuit(t, 2), honest)
	honest.Writes[1].Mask, honest.Writes[1].Value = privatelist.BlockBit, privatelist.BlockBit
	bound.RequireSolved(t, honest)
}

// Each case changes one wire of an honest batch, the host statement follows it and a predicate refuses.
func TestApplyRefusals(t *testing.T) {
	block := privatelist.BlockBit
	tests := []struct {
		name       string
		tamper     func(*privatelist.ApplyCircuit)
		permissive bool
	}{
		{"a value outside its mask", func(c *privatelist.ApplyCircuit) { c.Writes[0].Value = block | privatelist.AllowBit }, false},
		{"a mask past the leaf width", func(c *privatelist.ApplyCircuit) { c.Writes[0].Mask = block | 1<<privatelist.NLists }, false},
		{"a value past the leaf width", func(c *privatelist.ApplyCircuit) { c.Writes[0].Value = block | 1<<privatelist.NLists }, false},
		{"a mask naming a member-written list", func(c *privatelist.ApplyCircuit) { c.Writes[0].Mask = block | 1<<3 }, false},
		{"a mask naming the escrow list", func(c *privatelist.ApplyCircuit) { c.Writes[0].Mask = block | 1<<7 }, false},
		{"a mask dropping the block leaves another leaf", func(c *privatelist.ApplyCircuit) { c.Writes[0].Mask, c.Writes[0].Value = 0, 0 }, true},
		{"a member other than the leaf's", func(c *privatelist.ApplyCircuit) { c.Writes[0].Member = otherOne }, false},
		{"a salt other than the leaf's", func(c *privatelist.ApplyCircuit) { c.Writes[0].ListSalt = big.NewInt(0x0bad) }, false},
		{"a counter other than the published one", func(c *privatelist.ApplyCircuit) { c.Writes[0].WriteCounter = 99 }, false},
		{"another old leaf opening", func(c *privatelist.ApplyCircuit) { c.Writes[0].OldWritten, c.Writes[0].OldLeafSalt = 1, 7 }, false},
		{"old lists on an unwritten leaf", func(c *privatelist.ApplyCircuit) { c.Writes[0].OldLists = privatelist.AllowBit }, false},
		{"another path", func(c *privatelist.ApplyCircuit) { c.Writes[0].Siblings[40] = 1 }, false},
		{"a zero count", func(c *privatelist.ApplyCircuit) { c.Count = 0 }, false},
		{"a count past the width", func(c *privatelist.ApplyCircuit) { c.Count = 3 }, false},
		{"another new root", func(c *privatelist.ApplyCircuit) { c.NewRoot = 1 }, false},
		{"another chain end", func(c *privatelist.ApplyCircuit) { c.ChainEnd = 1 }, false},
	}
	_, honest := honestBatch(t, 2, true, setBlock(alice))
	bound := ringkey.Bind(t, applyCircuit(t, 2), honest)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, c := honestBatch(t, 2, true, setBlock(alice))
			tt.tamper(c)
			bindStatement(t, c, !tt.permissive)
			bound.Refuse(t, c)
		})
	}
}

// Without the mask rule a write could change a bit while claiming the permissive form.
func TestApplyCannotHideARestrictionFromTheBit(t *testing.T) {
	tree, honest := honestBatch(t, 2, true, ringprivatelist.Change{Owner: alice, ListSalt: salt, Mask: privatelist.BlockBit, Value: privatelist.BlockBit})
	bound := ringkey.Bind(t, applyCircuit(t, 2), honest)
	// The same published leaf with a permissive mask keeps no block bit, so it opens another leaf.
	honest.Writes[0].Mask, honest.Writes[0].Value = privatelist.AllowBit, privatelist.AllowBit
	bindStatement(t, honest, false)
	bound.Refuse(t, honest)
	if tree.Read(t, alice, salt).Lists != privatelist.BlockBit {
		t.Fatal("published leaf changed")
	}
}

func TestApplyRefusesAnUnshippedWidth(t *testing.T) {
	if _, err := privatelist.NewApplyCircuit(3); err == nil {
		t.Fatal("built width 3")
	}
}

func TestReaderRebuildsTheRootFromPublishedWrites(t *testing.T) {
	curator := ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
	tag := ringprivatelist.ListTag(t, salt)
	curator.WriteSalted(t, alice, salt, tag, privatelist.BlockBit, privatelist.BlockBit)
	curator.WriteUnenrolled(t, otherOne, privatelist.AllowBit, privatelist.AllowBit)
	curator.WriteSalted(t, alice, salt, tag, privatelist.BlockBit, 0)
	rebuilt := ringprivatelist.Rebuild(t, curator.Tree.Writes())
	if rebuilt.Root().Cmp(curator.Tree.Root()) != 0 {
		t.Fatal("rebuilt root differs")
	}
	// A salt holder opens the rebuilt tree with no curator.
	if opened := rebuilt.Read(t, alice, salt); !opened.Written || opened.Lists != 0 {
		t.Fatalf("opened %+v", opened)
	}
	if err := solveRow(rowFor(t, rebuilt, enrolled(t, alice, salt), salt, 0)); err != nil {
		t.Fatal(err)
	}
}

// Pins the stated disclosure, a dictionary over public keys finds salt 0 entries and no enrolled owner.
func TestDictionaryFindsOnlySaltZeroEntries(t *testing.T) {
	curator := ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
	curator.WriteSalted(t, alice, salt, ringprivatelist.ListTag(t, salt), privatelist.BlockBit, privatelist.BlockBit)
	curator.WriteUnenrolled(t, otherOne, privatelist.BlockBit, privatelist.BlockBit)
	found := map[string]bool{}
	for _, write := range curator.Tree.Writes() {
		for _, owner := range []*big.Int{alice, otherOne} {
			if ringprivatelist.Position(t, owner, noSalt).Cmp(write.Position) == 0 {
				found[owner.Text(16)] = true
			}
		}
	}
	if found[alice.Text(16)] || !found[otherOne.Text(16)] {
		t.Fatalf("dictionary found %v", found)
	}
	// Anyone opens the salt 0 entry, its leaf salt derives from public values.
	if opened := curator.Tree.Read(t, otherOne, noSalt); opened.Lists != privatelist.BlockBit {
		t.Fatalf("opened %+v", opened)
	}
}
