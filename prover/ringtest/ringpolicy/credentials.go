package ringpolicy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

func ListSaltIn(t testing.TB, owner, ringID *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, new(big.Int).Add(owner, big.NewInt(4)), ringID)
}

func ListSaltOf(t testing.TB, owner *big.Int) *big.Int {
	t.Helper()
	return ListSaltIn(t, owner, big.NewInt(ringID))
}

func Enroll(t testing.TB, tree *ringregistry.Credentials, owner, nullifierPk *big.Int) {
	t.Helper()
	tree.Insert(t, ringregistry.CredentialEntry{
		Member: owner, NullifierPk: nullifierPk,
		ListTag: ringregistry.ListTag(t, ListSaltOf(t, owner)), CtHash: new(big.Int).Add(owner, big.NewInt(1)),
	})
}

func FillCredentials(t testing.TB, target *policy.Credentials, tree *ringregistry.Credentials, rows, outputs []frontend.Variable, p *policy.Policy, payments []frontend.Variable) {
	t.Helper()
	openings := make([]policy.CredentialOpening, 0, len(target.Openings))
	seenMembers := map[string]int{}
	entry := func(member frontend.Variable) frontend.Variable {
		identity := ringtest.AsBigInt(member)
		if identity.Sign() == 0 {
			return 0
		}
		if index, found := seenMembers[identity.String()]; found {
			return index
		}
		index := len(openings)
		seenMembers[identity.String()] = index
		openings = append(openings, policy.CredentialOpening(tree.Opening(t, identity)))
		return index
	}
	for j, member := range rows {
		target.RowEntries[j] = entry(member)
	}
	for o, member := range outputs {
		target.OutputEntries[o] = entry(member)
	}
	if p != nil {
		for j := range rows {
			p.SenderEntries[j].Credential = target.RowEntries[j]
		}
		for o := range payments {
			p.OwnerEntries[o].Credential = 0
			if ringtest.AsBigInt(p.PolicyHash).Sign() != 0 && ringtest.AsBigInt(p.Salted).Sign() != 0 {
				p.OwnerEntries[o].Credential = entry(payments[o])
			}
		}
	}
	if len(openings) > len(target.Openings) {
		t.Fatalf("credential openings exceed capacity %d", len(target.Openings))
	}
	target.CredentialOwner, target.AddressRoot = tree.Owner, tree.AddressRoot()
	target.StateRoots = tree.StateRoots(len(target.StateRoots))
	for i := range target.Openings {
		target.Openings[i] = policy.CredentialOpening(ringregistry.ZeroCredentialOpening())
		if i < len(openings) {
			target.Openings[i] = openings[i]
		}
	}
}
