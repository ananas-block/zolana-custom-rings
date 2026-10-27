package registry_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type transitionCircuit struct {
	Roots   registry.RootTransition
	Proof   registry.SharedQuadProof
	Changes []registry.LeafChange
}

func (c *transitionCircuit) Define(api frontend.API) error {
	return c.Proof.AssertChanges(api, c.Roots, c.Changes)
}

func newTransition(t *testing.T, count int) *transitionCircuit {
	t.Helper()
	proof, err := registry.NewSharedQuadProof(count)
	if err != nil {
		t.Fatal(err)
	}
	return &transitionCircuit{Proof: proof, Changes: make([]registry.LeafChange, count)}
}

func transitionAssignment(t *testing.T, members *ringregistry.Registry, entries []ringregistry.Entry) *transitionCircuit {
	t.Helper()
	c := newTransition(t, 2*len(entries))
	proof, err := members.SharedProof(make([]uint64, len(c.Changes)))
	if err != nil {
		t.Fatal(err)
	}
	c.Proof = proof
	c.Roots.Old = members.Root()
	for i, entry := range entries {
		write := members.Apply(t, entry)
		low := registry.LeafChange{Enabled: 0, Before: 0, After: 0}
		slot := registry.LeafChange{Enabled: 0, Before: 0, After: 0}
		if write.Exists {
			before := ringregistry.Record{Member: entry.Member, Next: write.OldNext, Lists: write.OldLists, EscrowKey: write.OldEscrow, MintPolicy: write.OldMintPolicy, WithdrawalThreshold: write.OldWithdrawalThreshold}
			slot = registry.LeafChange{Enabled: 1, Before: before.Hash(t), After: members.Opening(entry.Member).Record.Hash(t)}
		} else {
			low = registry.LeafChange{Enabled: 1, Before: write.Low.Hash(t), After: write.Low.Hash(t)}
			if members.Opening(entry.Member).Present {
				relinked := write.Low
				relinked.Next = entry.Member
				low.After = relinked.Hash(t)
				slot = registry.LeafChange{Enabled: 1, Before: 0, After: members.Opening(entry.Member).Record.Hash(t)}
			}
		}
		c.Changes[2*i], c.Changes[2*i+1] = low, slot
		for offset, path := range []ringregistry.Path{write.LowPath, write.Slot} {
			position := 2*i + offset
			c.Proof.Paths[position].Index = path.Index
			for level := range c.Proof.Paths[position].Siblings {
				for child, value := range path.Siblings[level] {
					c.Proof.Paths[position].Siblings[level][child] = value
				}
			}
		}
	}
	c.Roots.New = members.Root()
	return c
}

func TestSharedQuadTransitionPreservesSequentialWrites(t *testing.T) {
	for _, count := range registry.ApplyWidths {
		for _, mode := range []string{"insert", "update", "mixed", "repeated", "empty"} {
			t.Run(fmt.Sprintf("%d/%s", count, mode), func(t *testing.T) {
				members := sharedRegistry(t)
				entries := make([]ringregistry.Entry, count)
				for i := range entries {
					member := int64(i*10 + 5)
					switch mode {
					case "update":
						member = int64((i + 1) * 10)
					case "mixed":
						if i%2 == 0 {
							member = 10
						}
					case "repeated":
						member = 5
					}
					value := int64(2)
					if mode == "empty" {
						value = 0
					}
					entries[i] = entry(member, 2, value, 0)
				}
				assignment := transitionAssignment(t, members, entries)
				if err := test.IsSolved(newTransition(t, 2*count), assignment, ecc.BN254.ScalarField()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSharedQuadTransitionRejectsInconsistentState(t *testing.T) {
	entries := []ringregistry.Entry{entry(5, 2, 2, 0), entry(10, 2, 2, 0), entry(5, 1, 1, 0)}
	for name, tamper := range map[string]func(*transitionCircuit){
		"old root":             func(c *transitionCircuit) { c.Roots.Old = 1 },
		"new root":             func(c *transitionCircuit) { c.Roots.New = 1 },
		"old leaf":             func(c *transitionCircuit) { c.Changes[0].Before = 0 },
		"new leaf":             func(c *transitionCircuit) { c.Changes[5].After = 0 },
		"nonboolean enable":    func(c *transitionCircuit) { c.Changes[0].Enabled = 2 },
		"skipped predecessor":  func(c *transitionCircuit) { c.Changes[0].Enabled = 0 },
		"skipped first write":  func(c *transitionCircuit) { c.Changes[0].Enabled, c.Changes[1].Enabled = 0, 0 },
		"stale slot leaf":      func(c *transitionCircuit) { c.Changes[5].Before = 0 },
		"stale slot path":      func(c *transitionCircuit) { c.Proof.Paths[5] = c.Proof.Paths[1] },
		"capacity alias":       func(c *transitionCircuit) { c.Proof.Paths[0].Index = registry.Capacity },
		"changed canopy route": func(c *transitionCircuit) { c.Proof.Paths[0].Index = 1 << 18 },
		"reversed mutation order": func(c *transitionCircuit) {
			c.Changes[0], c.Changes[1] = c.Changes[1], c.Changes[0]
			c.Proof.Paths[0], c.Proof.Paths[1] = c.Proof.Paths[1], c.Proof.Paths[0]
		},
	} {
		t.Run(name, func(t *testing.T) {
			assignment := transitionAssignment(t, sharedRegistry(t), entries)
			tamper(assignment)
			if err := test.IsSolved(newTransition(t, 2*len(entries)), assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("inconsistent transition accepted")
			}
		})
	}
}

type independentTransitionCircuit struct {
	Roots   registry.RootTransition
	Paths   []registry.QuadPath
	Changes []registry.LeafChange
}

func (c *independentTransitionCircuit) Define(api frontend.API) error {
	root := c.Roots.Old
	for i, change := range c.Changes {
		api.AssertIsBoolean(change.Enabled)
		before, after := c.Paths[i].Update(api, change.Before, change.After)
		api.AssertIsEqual(api.Mul(change.Enabled, api.Sub(before, root)), 0)
		root = api.Select(change.Enabled, after, root)
	}
	api.AssertIsEqual(root, c.Roots.New)
	return nil
}

func TestSharedQuadTransitionConstraintCounts(t *testing.T) {
	for _, writes := range registry.ApplyWidths {
		count := 2 * writes
		shared, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newTransition(t, count), frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		independent, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &independentTransitionCircuit{Paths: make([]registry.QuadPath, count), Changes: make([]registry.LeafChange, count)}, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("writes=%d independent=%d shared=%d reduction=%.2f%%", writes, independent.GetNbConstraints(), shared.GetNbConstraints(), 100*(1-float64(shared.GetNbConstraints())/float64(independent.GetNbConstraints())))
	}
}

func TestSharedQuadTransitionCompiledSolver(t *testing.T) {
	entries := []ringregistry.Entry{entry(5, 2, 2, 0), entry(10, 2, 2, 0), entry(15, 1, 0, 0), entry(5, 1, 1, 0)}
	c := newTransition(t, 2*len(entries))
	compiled, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	assignment := transitionAssignment(t, sharedRegistry(t), entries)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	assignment.Changes[7].Before = big.NewInt(0)
	witness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := compiled.IsSolved(witness); err == nil {
		t.Fatal("stale record accepted by compiled solver")
	}
}

func TestSharedQuadTransitionRejectsInvalidShape(t *testing.T) {
	c := newTransition(t, 2)
	c.Changes = nil
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c); err == nil {
		t.Fatal("missing transition accepted")
	}
}

func TestSharedQuadTransitionDistributedIndices(t *testing.T) {
	const count = 32
	c := newTransition(t, count)
	empty := [registry.Height + 1]*big.Int{big.NewInt(0)}
	nodes := [registry.Height + 1]map[uint64]*big.Int{}
	for level := range nodes {
		nodes[level] = map[uint64]*big.Int{}
		if level > 0 {
			previous := empty[level-1]
			empty[level] = ringtest.MustPoseidonHash(t, previous, previous, previous, previous)
		}
	}
	nodeAt := func(level int, index uint64) *big.Int {
		if value, found := nodes[level][index]; found {
			return value
		}
		return empty[level]
	}
	depth := len(c.Proof.Paths[0].Siblings)
	for i := range c.Proof.Canopy {
		c.Proof.Canopy[i] = empty[depth]
	}
	c.Roots.Old = empty[registry.Height]
	for i := range c.Changes {
		index := uint64(i * (registry.Capacity - 1) / (count - 1))
		if i%8 == 1 {
			index = uint64((i - 1) * (registry.Capacity - 1) / (count - 1))
		}
		c.Proof.Paths[i].Index = index
		c.Changes[i] = registry.LeafChange{Enabled: 1, Before: nodeAt(0, index), After: i + 1}
		for level := range c.Proof.Paths[i].Siblings {
			node := index >> (2 * level)
			first := node &^ (registry.Arity - 1)
			sibling := 0
			for child := first; child < first+registry.Arity; child++ {
				if child != node {
					c.Proof.Paths[i].Siblings[level][sibling] = nodeAt(level, child)
					sibling++
				}
			}
		}
		nodes[0][index] = big.NewInt(int64(i + 1))
		for level := 0; level < registry.Height; level++ {
			parent := index >> (2 * (level + 1))
			first := parent * registry.Arity
			nodes[level+1][parent] = ringtest.MustPoseidonHash(t, nodeAt(level, first), nodeAt(level, first+1), nodeAt(level, first+2), nodeAt(level, first+3))
		}
	}
	c.Roots.New = nodeAt(registry.Height, 0)
	if err := test.IsSolved(newTransition(t, count), c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedQuadTransitionSingleChange(t *testing.T) {
	members := sharedRegistry(t)
	c := newTransition(t, 1)
	proof, err := members.SharedProof([]uint64{1})
	if err != nil {
		t.Fatal(err)
	}
	c.Proof = proof
	c.Roots.Old = members.Root()
	before := members.Opening(big.NewInt(10)).Record.Hash(t)
	members.Apply(t, entry(10, 2, 2, 0))
	c.Changes[0] = registry.LeafChange{Enabled: 1, Before: before, After: members.Opening(big.NewInt(10)).Record.Hash(t)}
	c.Roots.New = members.Root()
	if err := test.IsSolved(newTransition(t, 1), c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	c.Changes[0].Enabled = 0
	c.Roots.New = c.Roots.Old
	if err := test.IsSolved(newTransition(t, 1), c, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
