package ringregistry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type credentialWriteCircuit struct {
	Write                       registry.CredentialWrite
	Roots                       registry.CredentialRoots
	Active, Member, AddressRoot frontend.Variable
}

func (c *credentialWriteCircuit) Define(api frontend.API) error {
	c.Write.Assert(api, c.Active, c.Member, c.AddressRoot, c.Roots.Check(api))
	return nil
}

func privateWriteFixture(t testing.TB) *credentialWriteCircuit {
	t.Helper()
	return privateWriteForSalt(t, big.NewInt(13))
}

func privateWriteForSalt(t testing.TB, salt *big.Int) *credentialWriteCircuit {
	t.Helper()
	credentials := credentialFixtureWithSalt(t, salt)
	member := big.NewInt(101)
	address := ringregistry.CredentialAddress(t, credentials.Owner, credentials.RingID, member)
	addresses := spptest.MustNewNullifierTree(t)
	index := addresses.NextIndex()
	proof, err := addresses.InsertWithWitness(address, protocol.NullifierTreeHeight)
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
	return &credentialWriteCircuit{
		Write: write, Active: 1, Member: ringregistry.ListKey(t, member, salt), AddressRoot: addresses.Root(),
		Roots: registry.CredentialRoots{RingID: credentials.RingID, Owner: credentials.Owner, StateRoots: credentials.StateRoots(1)},
	}
}

func TestPrivateWriteBindsCredentialAndAppliedAddress(t *testing.T) {
	requireCredentialSolved(t, privateWriteFixture(t))
	for _, tc := range []struct {
		name   string
		mutate func(*credentialWriteCircuit)
	}{
		{"wrong write key", func(c *credentialWriteCircuit) { c.Member = 107 }},
		{"wrong owner identity", func(c *credentialWriteCircuit) { c.Write.Member = 107 }},
		{"wrong salt", func(c *credentialWriteCircuit) {
			c.Write.ListSalt = 17
			c.Member = ringregistry.ListKey(t, ringtest.AsBigInt(c.Write.Member), big.NewInt(17))
		}},
		{"wrong credential owner", func(c *credentialWriteCircuit) { c.Roots.Owner = 109 }},
		{"wrong ring", func(c *credentialWriteCircuit) { c.Roots.RingID = 113 }},
		{"wrong state root", func(c *credentialWriteCircuit) { c.Roots.StateRoots[0][1] = 127 }},
		{"wrong address successor", func(c *credentialWriteCircuit) { c.Write.Address.Next = 131 }},
		{"wrong address root", func(c *credentialWriteCircuit) { c.AddressRoot = 137 }},
		{"wrong address path", func(c *credentialWriteCircuit) { c.Write.Address.Path[0] = 139 }},
		{"address index outside width", func(c *credentialWriteCircuit) { c.Write.Address.Index = uint64(1) << protocol.NullifierTreeHeight }},
		{"state inclusion without address application", func(c *credentialWriteCircuit) {
			c.AddressRoot = spptest.MustNewNullifierTree(t).Root()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := privateWriteFixture(t)
			tc.mutate(c)
			requireCredentialRefused(t, c, "registry.CredentialWrite.Assert")
		})
	}
}

func TestPrivateWriteRequiresCanonicalNonzeroSalt(t *testing.T) {
	for _, salt := range []*big.Int{new(big.Int), new(big.Int).Lsh(big.NewInt(1), 248)} {
		requireCredentialRefused(t, privateWriteForSalt(t, salt), "registry.CredentialWrite.Assert")
	}
}

func inactiveWriteFixture() *credentialWriteCircuit {
	c := &credentialWriteCircuit{
		Write:  ringregistry.ZeroCredentialWrite(),
		Roots:  registry.CredentialRoots{RingID: 0, Owner: 0, StateRoots: [][2]frontend.Variable{{0, 0}}},
		Active: 0, Member: 0, AddressRoot: 0,
	}
	return c
}

func TestInactivePrivateWriteHasOneEncoding(t *testing.T) {
	requireCredentialSolved(t, inactiveWriteFixture())
	for _, tc := range []struct {
		name   string
		mutate func(*credentialWriteCircuit)
	}{
		{"member", func(c *credentialWriteCircuit) { c.Write.Member = 1 }},
		{"salt", func(c *credentialWriteCircuit) { c.Write.ListSalt = 1 }},
		{"credential member", func(c *credentialWriteCircuit) { c.Write.Leaf.Member = 1 }},
		{"address successor", func(c *credentialWriteCircuit) { c.Write.Address.Next = 1 }},
		{"address index", func(c *credentialWriteCircuit) { c.Write.Address.Index = 1 }},
		{"address path", func(c *credentialWriteCircuit) { c.Write.Address.Path[0] = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := inactiveWriteFixture()
			tc.mutate(c)
			requireCredentialRefused(t, c, "registry.CredentialWrite.Assert")
		})
	}
}
