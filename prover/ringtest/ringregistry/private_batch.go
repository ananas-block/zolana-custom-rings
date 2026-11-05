package ringregistry

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// OwnerWrite is one enrolled owner of ring 71 whose address tree 0 applied.
type OwnerWrite struct {
	Credentials *Credentials
	Write       registry.CredentialWrite
	// Key is ListKey(member, salt), the member a private write names.
	Key         *big.Int
	AddressRoot *big.Int
}

// SaltedCredentials holds member 101 enrolled under salt.
func SaltedCredentials(t testing.TB, salt *big.Int) *Credentials {
	t.Helper()
	credentials := NewCredentials(t, big.NewInt(71))
	credentials.Insert(t, CredentialEntry{
		Member: big.NewInt(101), NullifierPk: spptest.MustNullifierPk(t, big.NewInt(7)),
		ListTag: ListTag(t, salt), CtHash: big.NewInt(17),
		Aud: [2]*big.Int{big.NewInt(19), big.NewInt(23)}, Eph: [2]*big.Int{big.NewInt(29), big.NewInt(31)},
	})
	return credentials
}

func NewOwnerWrite(t testing.TB, salt *big.Int) OwnerWrite {
	t.Helper()
	credentials := SaltedCredentials(t, salt)
	member := big.NewInt(101)
	addresses := spptest.MustNewNullifierTree(t)
	index := addresses.NextIndex()
	proof, err := addresses.InsertWithWitness(CredentialAddress(t, credentials.Owner, credentials.RingID, member), protocol.NullifierTreeHeight)
	if err != nil {
		t.Fatal(err)
	}
	write := registry.CredentialWrite{
		Member: member, ListSalt: salt, Leaf: credentials.Opening(t, member).Leaf,
		Address: registry.AddressLeaf{Next: proof.NextValue, Index: index},
	}
	for i, sibling := range proof.NewElementProof {
		write.Address.Path[i] = sibling
	}
	return OwnerWrite{Credentials: credentials, Write: write, Key: ListKey(t, member, salt), AddressRoot: addresses.Root()}
}

// PrivateBatch writes mask on the salted owner key at slot 0 of a private key of capacity writes, the other slots stay inactive.
func PrivateBatch(t testing.TB, capacity int, mask int64) *registry.PrivateApplyRecordsCircuit {
	t.Helper()
	owner := NewOwnerWrite(t, big.NewInt(13))
	c, err := registry.NewPrivateApplyRecordsCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	members := New(t)
	c.OldRoot, c.OldNextIndex, c.ChainStart = members.Root(), members.NextIndex(), 17
	c.Count, c.CredentialWrites = 1, 1
	c.PrivateRingID, c.CredentialOwner, c.AddressRoot = owner.Credentials.RingID, owner.Credentials.Owner, owner.AddressRoot
	copy(c.StateRoots, owner.Credentials.StateRoots(capacity))
	entry := Entry{Member: owner.Key, Mask: big.NewInt(mask), Value: big.NewInt(mask)}
	c.Writes[0], c.Credentials[0] = members.Apply(t, entry).Wires(), owner.Write
	for i := 1; i < capacity; i++ {
		c.Writes[i] = members.Apply(t, Entry{Member: big.NewInt(2), Mask: new(big.Int), Value: new(big.Int)}).Wires()
		c.Credentials[i] = ZeroCredentialWrite()
	}
	c.NewRoot, c.NewNextIndex = members.Root(), members.NextIndex()
	c.ChainEnd = ringtest.MustPoseidonHash(t, ringtest.AsBigInt(c.ChainStart), entry.Hash(t))
	BindPrivateBatch(t, c)
	return c
}

// BindPrivateBatch hashes the statement from the circuit's current values, as the program rebuilds it.
func BindPrivateBatch(t testing.TB, c *registry.PrivateApplyRecordsCircuit) {
	t.Helper()
	fields := []frontend.Variable{
		shared.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
		c.CredentialWrites, c.PrivateRingID, c.CredentialOwner, c.AddressRoot,
	}
	for _, root := range c.StateRoots {
		fields = append(fields, root[:]...)
	}
	c.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(fields))
}
