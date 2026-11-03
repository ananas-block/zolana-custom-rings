package registry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

const addressInvariant = "registry.RecordWrite.assertAddressMatchesEscrow"

var (
	addressRing  = big.NewInt(0x4152)
	nullifierKey = big.NewInt(0x6e6b)
	otherKey     = big.NewInt(0x6e6c)
	escrowCt     = big.NewInt(0xc7)
)

func boundAddress(member int64, nullifierPk *big.Int, revision uint64) ringregistry.Address {
	return ringregistry.Address{RingID: addressRing, Member: big.NewInt(member), NullifierPk: nullifierPk, ViewingKey: ringtest.Repeat(0x51), Revision: revision}
}

// addressWrite and escrowWrite stand for the only program paths that set either hash.
func addressWrite(t *testing.T, address ringregistry.Address, pair *ringregistry.Preimages) ringregistry.Entry {
	t.Helper()
	zero := big.NewInt(0)
	return ringregistry.Entry{Member: address.Member, Mask: zero, Value: zero, EscrowKey: zero, AddressHash: address.Hash(t), Pair: pair}
}

func escrowWrite(t *testing.T, member int64, nullifierPk *big.Int, pair *ringregistry.Preimages) ringregistry.Entry {
	t.Helper()
	return ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(ringregistry.EscrowBit), Value: big.NewInt(ringregistry.EscrowBit), EscrowKey: ringregistry.EscrowKey(t, nullifierPk, escrowCt), Pair: pair}
}

func requireInvariantRefused(t *testing.T, b *batch) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(applyCircuit(t, b.circuit.NumWrites), b.circuit, ecc.BN254.ScalarField()), addressInvariant)
}

// Both orders settle under one nullifier key, an unrelated write beside the pair opens no preimage.
func TestAddressAndEscrowAgreeInEitherOrder(t *testing.T) {
	address := boundAddress(0x20, nullifierKey, 1)
	pair := ringregistry.PairOf(address, escrowCt)
	t.Run("address then escrow", func(t *testing.T) {
		members := ringregistry.New(t)
		members.Apply(t, addressWrite(t, address, nil))
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), escrowWrite(t, 0x20, nullifierKey, pair)))
	})
	t.Run("escrow then address", func(t *testing.T) {
		members := ringregistry.New(t)
		members.Apply(t, escrowWrite(t, 0x20, nullifierKey, nil))
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), addressWrite(t, address, pair)))
	})
	t.Run("both in one batch", func(t *testing.T) {
		requireApplied(t, applyBatch(t, ringregistry.New(t), 2, big.NewInt(0), addressWrite(t, address, nil), escrowWrite(t, 0x20, nullifierKey, pair)))
	})
	t.Run("an unrelated write opens no preimage", func(t *testing.T) {
		members := ringregistry.New(t)
		members.Apply(t, addressWrite(t, address, nil))
		members.Apply(t, escrowWrite(t, 0x20, nullifierKey, pair))
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), entry(0x20, ringregistry.AllowBit, ringregistry.AllowBit, 0)))
	})
}

// A mismatch would have delivery bound to one spend key and escrow disclosing another, for every order of the two writes.
func TestAddressAndEscrowMismatchIsRefused(t *testing.T) {
	address := boundAddress(0x20, nullifierKey, 1)
	// The prover holds no preimage pair with one key, each case shows the closest witness.
	addressKey := ringregistry.PairOf(address, escrowCt)
	escrowKey := ringregistry.PairOf(boundAddress(0x20, otherKey, 1), escrowCt)
	for _, pair := range []*ringregistry.Preimages{addressKey, escrowKey} {
		t.Run("address then escrow", func(t *testing.T) {
			members := ringregistry.New(t)
			members.Apply(t, addressWrite(t, address, nil))
			requireInvariantRefused(t, applyBatch(t, members, 1, big.NewInt(0), escrowWrite(t, 0x20, otherKey, pair)))
		})
		t.Run("escrow then address", func(t *testing.T) {
			members := ringregistry.New(t)
			members.Apply(t, escrowWrite(t, 0x20, otherKey, nil))
			requireInvariantRefused(t, applyBatch(t, members, 1, big.NewInt(0), addressWrite(t, address, pair)))
		})
		t.Run("conflicting writes in one batch", func(t *testing.T) {
			requireInvariantRefused(t, applyBatch(t, ringregistry.New(t), 2, big.NewInt(0), addressWrite(t, address, nil), escrowWrite(t, 0x20, otherKey, pair)))
		})
	}
	t.Run("a rotation to another nullifier key beside the escrow", func(t *testing.T) {
		members := ringregistry.New(t)
		members.Apply(t, addressWrite(t, address, nil))
		members.Apply(t, escrowWrite(t, 0x20, nullifierKey, addressKey))
		rotated := boundAddress(0x20, otherKey, 2)
		requireInvariantRefused(t, applyBatch(t, members, 1, big.NewInt(0), addressWrite(t, rotated, ringregistry.PairOf(rotated, escrowCt))))
	})
}

// A write with no account behind it holds no preimage, zero wires open neither hash.
func TestPairingWriteWithoutPreimagesIsRefused(t *testing.T) {
	members := ringregistry.New(t)
	members.Apply(t, addressWrite(t, boundAddress(0x20, nullifierKey, 1), nil))
	requireInvariantRefused(t, applyBatch(t, members, 1, big.NewInt(0), escrowWrite(t, 0x20, nullifierKey, nil)))
}

// An authority batch can delay an address, its chained entry holds a zero hash and no root under another address settles.
func TestAuthorityBatchCannotSubstituteAnAddress(t *testing.T) {
	address := boundAddress(0x20, nullifierKey, 1)
	enrolled := func(t *testing.T) *ringregistry.Registry {
		t.Helper()
		members := ringregistry.New(t)
		members.Apply(t, addressWrite(t, address, nil))
		return members
	}
	listWrite := entry(0x20, ringregistry.AllowBit, ringregistry.AllowBit, 0)
	define := "registry.(*ApplyRecordsCircuit).Define"
	substituted := func(t *testing.T, hash *big.Int) *big.Int {
		t.Helper()
		forged := ringregistry.New(t)
		forged.Apply(t, ringregistry.Entry{Member: big.NewInt(0x20), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(ringregistry.AllowBit), EscrowKey: big.NewInt(0), AddressHash: hash})
		return forged.Root()
	}
	t.Run("a list write keeps the address", func(t *testing.T) {
		members := enrolled(t)
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), listWrite))
		if members.Opening(big.NewInt(0x20)).Record.AddressHash.Cmp(address.Hash(t)) != 0 {
			t.Fatal("a list write moved the address")
		}
	})
	t.Run("a root under another address", func(t *testing.T) {
		b := applyBatch(t, enrolled(t), 1, big.NewInt(0), listWrite)
		b.circuit.NewRoot = substituted(t, boundAddress(0x20, otherKey, 1).Hash(t))
		b.bind(t)
		ringtest.RequireRefused(t, solve(t, b.circuit), define)
	})
	t.Run("a root with the address cleared", func(t *testing.T) {
		b := applyBatch(t, enrolled(t), 1, big.NewInt(0), listWrite)
		b.circuit.NewRoot = substituted(t, big.NewInt(0))
		b.bind(t)
		ringtest.RequireRefused(t, solve(t, b.circuit), define)
	})
	t.Run("an entry the chain never held", func(t *testing.T) {
		b := applyBatch(t, enrolled(t), 1, big.NewInt(0), listWrite)
		honestEnd := b.circuit.ChainEnd
		w := b.writes[0]
		w.Entry.AddressHash = boundAddress(0x20, otherKey, 1).Hash(t)
		b.circuit.Writes[0] = writeWires(w)
		b.circuit.ChainEnd = honestEnd
		b.circuit.NewRoot = substituted(t, w.Entry.AddressHash)
		b.bind(t)
		ringtest.RequireRefused(t, solve(t, b.circuit), define)
	})
	t.Run("a predecessor relink keeps the address", func(t *testing.T) {
		members := enrolled(t)
		// 0x30 links after 0x20, the relink rewrites the enrolled low record.
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), entry(0x30, ringregistry.AllowBit, ringregistry.AllowBit, 0)))
		if members.Opening(big.NewInt(0x20)).Record.AddressHash.Cmp(address.Hash(t)) != 0 {
			t.Fatal("a relink moved the address")
		}
	})
	t.Run("an address only insert counts as nonempty", func(t *testing.T) {
		members := ringregistry.New(t)
		before := members.NextIndex()
		requireApplied(t, applyBatch(t, members, 1, big.NewInt(0), addressWrite(t, address, nil)))
		if members.NextIndex() != before+1 {
			t.Fatal("an address only write inserted nothing")
		}
	})
}

func requireApplied(t *testing.T, b *batch) {
	t.Helper()
	if err := solve(t, b.circuit); err != nil {
		t.Fatal(err)
	}
}
