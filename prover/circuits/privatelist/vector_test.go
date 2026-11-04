package privatelist_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
)

// listVector is test-vectors/registry/private-list.json, written by program-libs/member-registry/tests/private_list_vector.rs.
type listVector struct {
	Depth           int          `json:"depth"`
	EmptyRoot       ringtest.Hex `json:"empty_root"`
	NullifierSecret ringtest.Hex `json:"nullifier_secret"`
	ListSalt        ringtest.Hex `json:"list_salt"`
	ListTag         ringtest.Hex `json:"list_tag"`
	Batches         []struct {
		ChainStart    ringtest.Hex `json:"chain_start"`
		OldRoot       ringtest.Hex `json:"old_root"`
		NewRoot       ringtest.Hex `json:"new_root"`
		ChainEnd      ringtest.Hex `json:"chain_end"`
		Restrictive   bool         `json:"restrictive"`
		StatementHash ringtest.Hex `json:"statement_hash"`
		Writes        []struct {
			Owner        ringtest.Hex `json:"owner"`
			Enrolled     bool         `json:"enrolled"`
			Mask         uint64       `json:"mask"`
			Value        uint64       `json:"value"`
			WriteCounter uint64       `json:"write_counter"`
			Position     ringtest.Hex `json:"position"`
			Leaf         ringtest.Hex `json:"leaf"`
			EntryHash    ringtest.Hex `json:"entry_hash"`
			Root         ringtest.Hex `json:"root"`
		} `json:"writes"`
	} `json:"batches"`
}

func requireEqual(t *testing.T, name string, got, want *big.Int) {
	t.Helper()
	if got.Cmp(want) != 0 {
		t.Fatalf("%s %x, Rust %x", name, got, want)
	}
}

// The host twin rebuilds the Rust writes and the circuit accepts them under the Rust statement.
func TestApplyMatchesRustVectors(t *testing.T) {
	var v listVector
	ringtest.ReadVector(t, "registry/private-list.json", &v)
	if v.Depth != privatelist.Depth {
		t.Fatalf("depth %d", v.Depth)
	}
	requireEqual(t, "list salt", ringprivatelist.ListSalt(t, v.NullifierSecret.Int), v.ListSalt.Int)
	requireEqual(t, "list tag", ringprivatelist.ListTag(t, v.ListSalt.Int), v.ListTag.Int)
	tree := ringprivatelist.New(t)
	requireEqual(t, "empty root", tree.Root(), v.EmptyRoot.Int)
	for _, batch := range v.Batches {
		requireEqual(t, "old root", tree.Root(), batch.OldRoot.Int)
		c := applyCircuit(t, 2)
		for i := range c.Writes {
			c.Writes[i] = ringprivatelist.ZeroWrite()
		}
		chain := batch.ChainStart.Int
		for i, write := range batch.Writes {
			salt := big.NewInt(0)
			if write.Enrolled {
				salt = v.ListSalt.Int
			}
			applied := tree.Apply(t, ringprivatelist.Change{Owner: write.Owner.Int, ListSalt: salt, Mask: write.Mask, Value: write.Value}, write.WriteCounter)
			requireEqual(t, "position", applied.Published.Position, write.Position.Int)
			requireEqual(t, "leaf", applied.Published.Leaf, write.Leaf.Int)
			requireEqual(t, "entry hash", applied.Published.EntryHash(t), write.EntryHash.Int)
			requireEqual(t, "root", tree.Root(), write.Root.Int)
			chain = ringtest.MustPoseidonHash(t, chain, applied.Published.EntryHash(t))
			c.Writes[i] = applied.Wires
		}
		requireEqual(t, "new root", tree.Root(), batch.NewRoot.Int)
		requireEqual(t, "chain end", chain, batch.ChainEnd.Int)
		c.OldRoot, c.NewRoot, c.ChainStart, c.ChainEnd, c.Count = batch.OldRoot.Int, batch.NewRoot.Int, batch.ChainStart.Int, chain, len(batch.Writes)
		c.PublicInputHash = batch.StatementHash.Int
		if err := test.IsSolved(applyCircuit(t, 2), c, ecc.BN254.ScalarField()); err != nil {
			t.Fatal(err)
		}
	}
}
