// Package ringprivatelist is the host twin of circuits/privatelist for the Go tests.
package ringprivatelist

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

var routeMask = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), privatelist.Depth), big.NewInt(1))

func ListSalt(t testing.TB, nullifierSecret *big.Int) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListSaltDomain), nullifierSecret)
}

func ListTag(t testing.TB, listSalt *big.Int) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListTagDomain), listSalt)
}

func Position(t testing.TB, owner, listSalt *big.Int) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListPositionDomain), owner, listSalt)
}

func LeafSalt(t testing.TB, listSalt *big.Int, writeCounter uint64) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListLeafSaltDomain), listSalt, new(big.Int).SetUint64(writeCounter))
}

func Leaf(t testing.TB, position *big.Int, lists uint64, leafSalt *big.Int) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListLeafDomain), position, new(big.Int).SetUint64(lists), leafSalt)
}

// Published is all a write shows, a reader rebuilds the tree from these alone.
type Published struct {
	Position, Leaf *big.Int
	WriteCounter   uint64
}

func (p Published) EntryHash(t testing.TB) *big.Int {
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListWriteDomain), p.Position, p.Leaf, new(big.Int).SetUint64(p.WriteCounter))
}

// Tree is the public tree anyone rebuilds, it holds no salt and no list bits.
type Tree struct {
	nodes  map[string]*big.Int
	zeros  [privatelist.Depth + 1]*big.Int
	writes []Published
}

func New(t testing.TB) *Tree {
	t.Helper()
	tree := &Tree{nodes: map[string]*big.Int{}}
	tree.zeros[0] = big.NewInt(0)
	for level := range privatelist.Depth {
		tree.zeros[level+1] = ringtest.MustPoseidonHash(t, tree.zeros[level], tree.zeros[level])
	}
	return tree
}

func Rebuild(t testing.TB, writes []Published) *Tree {
	t.Helper()
	tree := New(t)
	for _, write := range writes {
		tree.Publish(t, write)
	}
	return tree
}

func (tr *Tree) Root() *big.Int {
	return tr.node(privatelist.Depth, big.NewInt(0))
}

func (tr *Tree) Writes() []Published {
	return tr.writes
}

func (tr *Tree) node(level int, prefix *big.Int) *big.Int {
	if node, ok := tr.nodes[nodeKey(level, prefix)]; ok {
		return node
	}
	return tr.zeros[level]
}

func nodeKey(level int, prefix *big.Int) string {
	return fmt.Sprintf("%d/%s", level, prefix.Text(16))
}

func route(position *big.Int) *big.Int {
	return new(big.Int).And(position, routeMask)
}

// Siblings runs leaf level first.
func (tr *Tree) Siblings(position *big.Int) [privatelist.Depth]*big.Int {
	var siblings [privatelist.Depth]*big.Int
	prefix := route(position)
	for level := range privatelist.Depth {
		neighbour := new(big.Int).Xor(prefix, big.NewInt(1))
		siblings[level] = tr.node(level, neighbour)
		prefix = new(big.Int).Rsh(prefix, 1)
	}
	return siblings
}

func (tr *Tree) Publish(t testing.TB, write Published) {
	t.Helper()
	tr.writes = append(tr.writes, write)
	node := write.Leaf
	prefix := route(write.Position)
	tr.nodes[nodeKey(0, prefix)] = node
	for level := range privatelist.Depth {
		neighbour := tr.node(level, new(big.Int).Xor(prefix, big.NewInt(1)))
		if prefix.Bit(0) == 0 {
			node = ringtest.MustPoseidonHash(t, node, neighbour)
		} else {
			node = ringtest.MustPoseidonHash(t, neighbour, node)
		}
		prefix = new(big.Int).Rsh(prefix, 1)
		tr.nodes[nodeKey(level+1, prefix)] = node
	}
}

// OpenedLeaf is a salt holder's read of a position, Written unset on the empty leaf.
type OpenedLeaf struct {
	Written  bool
	Lists    uint64
	LeafSalt *big.Int
}

// Read trials every bitmap against the position's last write, needing no curator.
func (tr *Tree) Read(t testing.TB, owner, listSalt *big.Int) OpenedLeaf {
	t.Helper()
	position := Position(t, owner, listSalt)
	for i := len(tr.writes) - 1; i >= 0; i-- {
		write := tr.writes[i]
		if write.Position.Cmp(position) != 0 {
			continue
		}
		leafSalt := LeafSalt(t, listSalt, write.WriteCounter)
		for lists := range uint64(1 << privatelist.NLists) {
			if Leaf(t, position, lists, leafSalt).Cmp(write.Leaf) == 0 {
				return OpenedLeaf{Written: true, Lists: lists, LeafSalt: leafSalt}
			}
		}
		t.Fatalf("no bitmap opens position %x under this salt", position)
	}
	return OpenedLeaf{LeafSalt: big.NewInt(0)}
}

// Opening is the wires of this salt's read at owner's position.
func (tr *Tree) Opening(t testing.TB, owner, listSalt *big.Int) privatelist.Opening {
	t.Helper()
	opened := tr.Read(t, owner, listSalt)
	return OpeningWires(opened, tr.Siblings(Position(t, owner, listSalt)))
}

func OpeningWires(opened OpenedLeaf, siblings [privatelist.Depth]*big.Int) privatelist.Opening {
	opening := privatelist.Opening{Written: ringtest.Bit(opened.Written), Lists: new(big.Int).SetUint64(opened.Lists), LeafSalt: opened.LeafSalt}
	for level := range siblings {
		opening.Siblings[level] = siblings[level]
	}
	return opening
}

// Row is the row of an owner holding listSalt, salt zero for an unenrolled owner.
func (tr *Tree) Row(t testing.TB, owner, listSalt *big.Int) privatelist.Row {
	t.Helper()
	return privatelist.Row{Live: 1, ListSalt: listSalt, Salted: tr.Opening(t, owner, listSalt), Zero: tr.Opening(t, owner, big.NewInt(0))}
}

// PaddingRow proves nothing and serves no query.
func PaddingRow() privatelist.Row {
	return privatelist.Row{Live: 0, ListSalt: 0, Salted: zeroOpening(), Zero: zeroOpening()}
}

func zeroOpening() privatelist.Opening {
	opening := privatelist.Opening{Written: 0, Lists: 0, LeafSalt: 0}
	for level := range opening.Siblings {
		opening.Siblings[level] = 0
	}
	return opening
}

// Change is what a curator writes, the program never reads it.
type Change struct {
	Owner, ListSalt *big.Int
	Mask, Value     uint64
}

// Applied is one write's proof input with the published form it landed as.
type Applied struct {
	Wires     privatelist.Write
	Published Published
}

// Apply writes change under counter, a list byte outside its mask is the caller's refusal case.
func (tr *Tree) Apply(t testing.TB, change Change, counter uint64) Applied {
	t.Helper()
	position := Position(t, change.Owner, change.ListSalt)
	old := tr.Read(t, change.Owner, change.ListSalt)
	siblings := tr.Siblings(position)
	wires := privatelist.Write{
		Member: change.Owner, ListSalt: change.ListSalt, WriteCounter: counter,
		Mask: change.Mask, Value: change.Value,
		OldWritten: ringtest.Bit(old.Written), OldLists: old.Lists, OldLeafSalt: old.LeafSalt,
	}
	for level := range siblings {
		wires.Siblings[level] = siblings[level]
	}
	lists := old.Lists&^change.Mask | change.Value
	published := Published{Position: position, Leaf: Leaf(t, position, lists, LeafSalt(t, change.ListSalt, counter)), WriteCounter: counter}
	tr.Publish(t, published)
	return Applied{Wires: wires, Published: published}
}

// ZeroWrite pads a batch past its count.
func ZeroWrite() privatelist.Write {
	write := privatelist.Write{Member: 0, ListSalt: 0, WriteCounter: 0, Mask: 0, Value: 0, OldWritten: 0, OldLists: 0, OldLeafSalt: 0}
	for level := range write.Siblings {
		write.Siblings[level] = 0
	}
	return write
}

// Curator holds the write counter a storage registry publishes.
type Curator struct {
	Tree    *Tree
	Counter uint64
}

// WriteSalted writes an applied tracking row's owner, a salt off its list tag is refused ahead of any proof.
func (c *Curator) WriteSalted(t testing.TB, owner, listSalt, listTag *big.Int, mask, value uint64) Applied {
	t.Helper()
	if ListTag(t, listSalt).Cmp(listTag) != 0 {
		t.Fatal("salt does not open the tracking row's list tag")
	}
	return c.write(t, Change{Owner: owner, ListSalt: listSalt, Mask: mask, Value: value})
}

// WriteUnenrolled is public by construction, an enrolled owner never takes it.
func (c *Curator) WriteUnenrolled(t testing.TB, owner *big.Int, mask, value uint64) Applied {
	t.Helper()
	return c.write(t, Change{Owner: owner, ListSalt: big.NewInt(0), Mask: mask, Value: value})
}

func (c *Curator) write(t testing.TB, change Change) Applied {
	t.Helper()
	c.Counter++
	return c.Tree.Apply(t, change, c.Counter)
}
