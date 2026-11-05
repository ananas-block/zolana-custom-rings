package ringregistry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

type inclusionCircuit struct {
	Leaf   registry.CredentialLeaf
	Roots  registry.CredentialRoots
	Active frontend.Variable
}

func (c *inclusionCircuit) Define(api frontend.API) error {
	c.Leaf.AssertInclusion(api, c.Active, c.Roots)
	return nil
}

func credentialFixture(t testing.TB) *ringregistry.Credentials {
	t.Helper()
	return credentialFixtureWithSalt(t, big.NewInt(13))
}

func credentialFixtureWithSalt(t testing.TB, salt *big.Int) *ringregistry.Credentials {
	t.Helper()
	return ringregistry.SaltedCredentials(t, salt)
}

func inclusionFixture(t testing.TB) *inclusionCircuit {
	t.Helper()
	credentials := credentialFixture(t)
	return &inclusionCircuit{
		Leaf: credentials.Opening(t, big.NewInt(101)).Leaf, Active: 1,
		Roots: registry.CredentialRoots{RingID: credentials.RingID, Owner: credentials.Owner, StateRoots: credentials.StateRoots(2)},
	}
}

func requireCredentialSolved(t testing.TB, circuit frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func requireCredentialRefused(t testing.TB, circuit frontend.Circuit, frame string) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()), frame)
}

func TestCredentialStateInclusionBindsPayload(t *testing.T) {
	requireCredentialSolved(t, inclusionFixture(t))
	t.Run("selected repeated root", func(t *testing.T) {
		c := inclusionFixture(t)
		c.Leaf.TreeSlot = 1
		requireCredentialSolved(t, c)
	})
	for _, tc := range []struct {
		name   string
		mutate func(*inclusionCircuit)
	}{
		{"wrong statement owner", func(c *inclusionCircuit) { c.Roots.Owner = 103 }},
		{"wrong statement ring", func(c *inclusionCircuit) { c.Roots.RingID = 73 }},
		{"wrong leaf ring", func(c *inclusionCircuit) { c.Leaf.RingID = 73 }},
		{"wrong member", func(c *inclusionCircuit) { c.Leaf.Member = 107 }},
		{"wrong nullifier key", func(c *inclusionCircuit) { c.Leaf.NullifierPk = 109 }},
		{"wrong list tag", func(c *inclusionCircuit) { c.Leaf.ListTag = 113 }},
		{"wrong auditor", func(c *inclusionCircuit) { c.Leaf.Aud[0] = 127 }},
		{"wrong ephemeral key", func(c *inclusionCircuit) { c.Leaf.Eph[1] = 131 }},
		{"wrong ciphertext", func(c *inclusionCircuit) { c.Leaf.CtHash = 137 }},
		{"wrong blinding", func(c *inclusionCircuit) { c.Leaf.Blinding = 139 }},
		{"wrong state path", func(c *inclusionCircuit) { c.Leaf.StatePath[0] = 149 }},
		{"wrong state root", func(c *inclusionCircuit) { c.Roots.StateRoots[0][1] = 151 }},
		{"wrong tree id", func(c *inclusionCircuit) { c.Roots.StateRoots[0][0] = 5 }},
		{"tree id outside width", func(c *inclusionCircuit) { c.Roots.StateRoots[0][0] = 1 << 16 }},
		{"state index outside width", func(c *inclusionCircuit) { c.Leaf.StateIndex = uint64(1) << protocol.StateTreeHeight }},
		{"state slot outside table", func(c *inclusionCircuit) { c.Leaf.TreeSlot = len(c.Roots.StateRoots) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := inclusionFixture(t)
			tc.mutate(c)
			requireCredentialRefused(t, c, "registry.CredentialLeaf.AssertInclusion")
		})
	}
}

func TestCredentialRejectsZeroNullifierKeys(t *testing.T) {
	for _, key := range []*big.Int{new(big.Int), shared.ZeroNullifierPk} {
		credentials := ringregistry.NewCredentials(t, big.NewInt(71))
		credentials.Insert(t, ringregistry.CredentialEntry{Member: big.NewInt(101), NullifierPk: key, ListTag: big.NewInt(13)})
		c := &inclusionCircuit{
			Leaf: credentials.Opening(t, big.NewInt(101)).Leaf, Active: 1,
			Roots: registry.CredentialRoots{RingID: credentials.RingID, Owner: credentials.Owner, StateRoots: credentials.StateRoots(1)},
		}
		requireCredentialRefused(t, c, "registry.CredentialLeaf.AssertInclusion")
	}
}

type credentialPoolCircuit struct {
	policy.Credentials
	RingID, Member, Entry, ExpectedKey, ExpectedTag frontend.Variable
}

func (c *credentialPoolCircuit) Define(api frontend.API) error {
	pool := c.OpenCredentials(api, c.RingID)
	row := pool.Row(api, 1, c.Member, c.Entry)
	api.AssertIsEqual(row.NullifierPk, c.ExpectedKey)
	api.AssertIsEqual(row.ListTag, c.ExpectedTag)
	return nil
}

func poolFixture(t testing.TB) *credentialPoolCircuit {
	t.Helper()
	tree := credentialFixture(t)
	credentials, err := policy.NewCredentials(1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	credentials.CredentialOwner, credentials.AddressRoot, credentials.StateRoots = tree.Owner, tree.AddressRoot(), tree.StateRoots(3)
	credentials.Openings = []policy.CredentialOpening{policy.CredentialOpening(tree.Opening(t, big.NewInt(101))), policy.CredentialOpening(tree.Opening(t, big.NewInt(103))), policy.CredentialOpening(ringregistry.ZeroCredentialOpening())}
	credentials.RowEntries[0] = 0
	for i := range credentials.OutputEntries {
		credentials.OutputEntries[i] = 0
	}
	return &credentialPoolCircuit{Credentials: credentials, RingID: tree.RingID, Member: 101, Entry: 0, ExpectedKey: credentials.Openings[0].Leaf.NullifierPk, ExpectedTag: credentials.Openings[0].Leaf.ListTag}
}

func TestCredentialPoolAuthenticatesBothBranches(t *testing.T) {
	t.Run("state inclusion before address application", func(t *testing.T) { requireCredentialSolved(t, poolFixture(t)) })
	t.Run("absent member", func(t *testing.T) {
		c := poolFixture(t)
		c.Member, c.Entry, c.ExpectedKey, c.ExpectedTag = 103, 1, 0, 0
		requireCredentialSolved(t, c)
	})
	for _, tc := range []struct {
		name   string
		mutate func(*credentialPoolCircuit)
	}{
		{"present gap low", func(c *credentialPoolCircuit) { c.Openings[0].Gap.Low = 1 }},
		{"present gap successor", func(c *credentialPoolCircuit) { c.Openings[0].Gap.Next = 1 }},
		{"present gap index", func(c *credentialPoolCircuit) { c.Openings[0].Gap.Index = 1 }},
		{"present gap path", func(c *credentialPoolCircuit) { c.Openings[0].Gap.Path[0] = 1 }},
		{"absent ring", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.RingID = 1 }},
		{"absent key", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.NullifierPk = 1 }},
		{"absent tag", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.ListTag = 1 }},
		{"absent auditor", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.Aud[1] = 1 }},
		{"absent ephemeral key", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.Eph[0] = 1 }},
		{"absent ciphertext", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.CtHash = 1 }},
		{"absent blinding", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.Blinding = 1 }},
		{"absent tree slot", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.TreeSlot = 1 }},
		{"absent state index", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.StateIndex = 1 }},
		{"absent state path", func(c *credentialPoolCircuit) { c.Openings[1].Leaf.StatePath[0] = 1 }},
		{"wrong absence root", func(c *credentialPoolCircuit) { c.AddressRoot = 1 }},
		{"wrong absence path", func(c *credentialPoolCircuit) { c.Openings[1].Gap.Path[0] = 1 }},
		{"absence index outside width", func(c *credentialPoolCircuit) { c.Openings[1].Gap.Index = uint64(1) << protocol.NullifierTreeHeight }},
		{"nonboolean presence", func(c *credentialPoolCircuit) { c.Openings[0].Present = 2 }},
		{"padding marked present", func(c *credentialPoolCircuit) { c.Openings[2].Present = 1 }},
		{"duplicate present member", func(c *credentialPoolCircuit) { c.Openings[2] = c.Openings[0] }},
		{"duplicate present and absent member", func(c *credentialPoolCircuit) {
			empty := ringregistry.NewCredentials(t, ringtest.AsBigInt(c.RingID))
			c.Openings[2] = policy.CredentialOpening(empty.Opening(t, big.NewInt(101)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := poolFixture(t)
			tc.mutate(c)
			requireCredentialRefused(t, c, "policy.(*Credentials).OpenCredentials")
		})
	}
	t.Run("query names another member", func(t *testing.T) {
		c := poolFixture(t)
		c.Entry = 1
		requireCredentialRefused(t, c, "policy.CredentialPool.Row")
	})
}

func TestCredentialAbsenceRequiresStrictAddressGap(t *testing.T) {
	for _, boundary := range []string{"low", "next"} {
		t.Run(boundary, func(t *testing.T) {
			c := poolFixture(t)
			opening := &c.Openings[1]
			address := ringregistry.CredentialAddress(t, ringtest.AsBigInt(c.CredentialOwner), ringtest.AsBigInt(c.RingID), ringtest.AsBigInt(opening.Leaf.Member))
			if boundary == "low" {
				opening.Gap.Low = address
			} else {
				opening.Gap.Next = address
			}
			leaf := ringtest.MustPoseidonHash(t, ringtest.AsBigInt(opening.Gap.Low), ringtest.AsBigInt(opening.Gap.Next))
			root, err := protocol.MerkleRoot(leaf, ringtest.ToBigInts(opening.Gap.Path[:]), ringtest.AsBigInt(opening.Gap.Index).Uint64())
			if err != nil {
				t.Fatal(err)
			}
			c.AddressRoot = root
			requireCredentialRefused(t, c, "registry.AddressGap.AssertAbsent")
		})
	}
}
