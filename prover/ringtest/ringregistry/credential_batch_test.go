package ringregistry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func credentialBatch(t testing.TB) *registry.ApplyRecordsCircuit {
	t.Helper()
	return credentialBatchForMask(t, ringregistry.PrivateBlockBit)
}

func credentialBatchForMask(t testing.TB, mask int64) *registry.ApplyRecordsCircuit {
	t.Helper()
	private := privateWriteFixture(t)
	c, err := registry.NewApplyRecordsCircuit(2)
	if err != nil {
		t.Fatal(err)
	}
	members := ringregistry.New(t)
	c.OldRoot, c.OldNextIndex, c.ChainStart = members.Root(), members.NextIndex(), 17
	c.Count, c.CredentialWrites = 1, 1
	c.PrivateRingID, c.CredentialOwner, c.AddressRoot = private.Roots.RingID, private.Roots.Owner, private.AddressRoot
	c.StateRoots[0], c.StateRoots[1] = private.Roots.StateRoots[0], private.Roots.StateRoots[0]
	c.Credentials[0], c.Credentials[1] = private.Write, inactiveWriteFixture().Write
	entry := ringregistry.Entry{Member: ringtest.AsBigInt(private.Member), Mask: big.NewInt(mask), Value: big.NewInt(mask)}
	c.Writes[0] = members.Apply(t, entry).Wires()
	padding := members.Apply(t, ringregistry.Entry{Member: big.NewInt(2), Mask: new(big.Int), Value: new(big.Int)}).Wires()
	c.Writes[1] = padding
	c.NewRoot, c.NewNextIndex = members.Root(), members.NextIndex()
	c.ChainEnd = ringtest.MustPoseidonHash(t, ringtest.AsBigInt(c.ChainStart), entry.Hash(t))
	rebindCredentialBatch(t, c)
	return c
}

func rebindCredentialBatch(t testing.TB, c *registry.ApplyRecordsCircuit) {
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

func TestPrivateWriteBatchBindsClassification(t *testing.T) {
	requireCredentialSolved(t, credentialBatch(t))
	for _, tc := range []struct {
		name   string
		mutate func(*registry.ApplyRecordsCircuit)
	}{
		{"credential bit past count", func(c *registry.ApplyRecordsCircuit) {
			c.CredentialWrites = 3
			c.Writes[1], c.Credentials[1] = c.Writes[0], c.Credentials[0]
		}},
		{"credential bit past capacity", func(c *registry.ApplyRecordsCircuit) { c.CredentialWrites = 4 }},
		{"bitmap cleared with private witnesses", func(c *registry.ApplyRecordsCircuit) { c.CredentialWrites = 0 }},
		{"substituted write member", func(c *registry.ApplyRecordsCircuit) { c.Writes[0].Entry.Member = 2 }},
		{"substituted credential member", func(c *registry.ApplyRecordsCircuit) { c.Credentials[0].Member = 103 }},
		{"wrong address checkpoint", func(c *registry.ApplyRecordsCircuit) { c.AddressRoot = 19 }},
		{"empty ring", func(c *registry.ApplyRecordsCircuit) { c.PrivateRingID = 0 }},
		{"empty credential owner", func(c *registry.ApplyRecordsCircuit) { c.CredentialOwner = 0 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := credentialBatch(t)
			tc.mutate(c)
			rebindCredentialBatch(t, c)
			requireCredentialRefused(t, c, "registry.(*ApplyRecordsCircuit).Define")
		})
	}
}

func TestPrivateWriteClassificationRejectsPublicMask(t *testing.T) {
	requireCredentialRefused(t, credentialBatchForMask(t, ringregistry.AllowBit), "registry.(*ApplyRecordsCircuit).Define")
}

func TestPrivateWriteValueCannotSetUnmaskedBits(t *testing.T) {
	c := credentialBatchForMask(t, ringregistry.PrivateBlockBit|ringregistry.AllowBit)
	c.Writes[0].Entry.Mask = ringregistry.PrivateBlockBit
	entry := ringregistry.Entry{
		Member: ringtest.AsBigInt(c.Writes[0].Entry.Member), Mask: big.NewInt(ringregistry.PrivateBlockBit),
		Value: big.NewInt(ringregistry.PrivateBlockBit | ringregistry.AllowBit),
	}
	c.ChainEnd = ringtest.MustPoseidonHash(t, ringtest.AsBigInt(c.ChainStart), entry.Hash(t))
	rebindCredentialBatch(t, c)
	requireCredentialRefused(t, c, "registry.RecordWriteProofInput.apply")
}

func publicWriteBatch(t testing.TB) *registry.ApplyRecordsCircuit {
	t.Helper()
	c := credentialBatchForMask(t, ringregistry.AllowBit)
	c.CredentialWrites, c.PrivateRingID, c.CredentialOwner, c.AddressRoot = 0, 0, 0, 0
	for i := range c.StateRoots {
		c.StateRoots[i] = [2]frontend.Variable{0, 0}
		c.Credentials[i] = inactiveWriteFixture().Write
	}
	rebindCredentialBatch(t, c)
	return c
}

func TestPublicWriteHasCanonicalEmptyCredentialRead(t *testing.T) {
	requireCredentialSolved(t, publicWriteBatch(t))
	for _, tc := range []struct {
		name   string
		mutate func(*registry.ApplyRecordsCircuit)
	}{
		{"ring", func(c *registry.ApplyRecordsCircuit) { c.PrivateRingID = 1 }},
		{"credential owner", func(c *registry.ApplyRecordsCircuit) { c.CredentialOwner = 1 }},
		{"address root", func(c *registry.ApplyRecordsCircuit) { c.AddressRoot = 1 }},
		{"state tree id", func(c *registry.ApplyRecordsCircuit) { c.StateRoots[1][0] = 1 }},
		{"state root", func(c *registry.ApplyRecordsCircuit) { c.StateRoots[1][1] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := publicWriteBatch(t)
			tc.mutate(c)
			rebindCredentialBatch(t, c)
			requireCredentialRefused(t, c, "registry.(*ApplyRecordsCircuit).credentialBits")
		})
	}
}
