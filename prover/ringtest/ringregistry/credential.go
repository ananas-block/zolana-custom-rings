package ringregistry

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type CredentialEntry struct {
	Member, NullifierPk, ListTag, CtHash *big.Int
	Aud, Eph                             [2]*big.Int
}

type CredentialOpening struct {
	Present frontend.Variable
	Leaf    registry.CredentialLeaf
	Gap     registry.AddressGap
}

type Credentials struct {
	RingID, Owner *big.Int
	TreeID        uint16
	entries       []CredentialEntry
	root          *big.Int
	proofs        map[uint64]protocol.StateTreeWitness
	addresses     *protocol.NullifierTree
}

func CredentialProgram() [32]byte {
	return ringtest.Repeat(0x90)
}

func credentialOwner(t testing.TB) *big.Int {
	t.Helper()
	var identities struct {
		Cases []struct {
			RingProgram string       `json:"ring_program"`
			Owner       ringtest.Hex `json:"credential_owner"`
		} `json:"cases"`
	}
	ringtest.ReadVector(t, "registry/credential-owners.json", &identities)
	program := CredentialProgram()
	for _, identity := range identities.Cases {
		if bytes.Equal(ringtest.VectorBytes(t, identity.RingProgram, len(program)), program[:]) {
			if identity.Owner.Int == nil || identity.Owner.Sign() == 0 {
				t.Fatal("credential owner fixture is invalid")
			}
			return copied(identity.Owner.Int)
		}
	}
	t.Fatal("credential owner fixture is absent")
	return nil
}

func NewCredentials(t testing.TB, ringID *big.Int) *Credentials {
	t.Helper()
	c := &Credentials{RingID: copied(ringID), Owner: credentialOwner(t), TreeID: 3, addresses: spptest.MustNewNullifierTree(t)}
	c.rebuild(t)
	return c
}

func (c *Credentials) Insert(t testing.TB, entry CredentialEntry) {
	t.Helper()
	for _, previous := range c.entries {
		if previous.Member.Cmp(entry.Member) == 0 {
			t.Fatal("duplicate credential member")
		}
	}
	c.entries = append(c.entries, entry)
	c.rebuild(t)
}

func (c *Credentials) StateRoots(capacity int) [][2]frontend.Variable {
	roots := make([][2]frontend.Variable, capacity)
	for i := range roots {
		roots[i] = [2]frontend.Variable{int(c.TreeID), copied(c.root)}
	}
	return roots
}

func (c *Credentials) AddressRoot() *big.Int {
	return c.addresses.Root()
}

func (c *Credentials) Opening(t testing.TB, member *big.Int) CredentialOpening {
	t.Helper()
	opening := ZeroCredentialOpening()
	opening.Leaf.Member = copied(member)
	if member.Sign() == 0 {
		return opening
	}
	for i, entry := range c.entries {
		if entry.Member.Cmp(member) == 0 {
			opening.Present = 1
			opening.Leaf = c.leaf(t, entry)
			proof := c.proofs[uint64(i)]
			opening.Leaf.StateIndex = proof.PathIndex
			for level, sibling := range proof.PathElements {
				opening.Leaf.StatePath[level] = copied(sibling)
			}
			return opening
		}
	}
	gap := spptest.MustNonInclusion(t, c.addresses, CredentialAddress(t, c.Owner, c.RingID, member))
	opening.Gap.Low, opening.Gap.Next, opening.Gap.Index = gap.LowValue, gap.NextValue, gap.LowIndex
	for i, sibling := range gap.PathElements {
		opening.Gap.Path[i] = copied(sibling)
	}
	return opening
}

func CredentialAddress(t testing.TB, owner, ringID, member *big.Int) *big.Int {
	t.Helper()
	seed := ringtest.MustPoseidonHash(t, big.NewInt(shared.CredentialSeedDomain), ringID, member)
	zero := new(big.Int)
	address := spptest.MustUtxoHash(t, protocol.Utxo{
		Domain: big.NewInt(protocol.AddressDomain), Owner: owner, Asset: zero, Amount: zero,
		Blinding: seed, DataHash: zero, RingDataHash: zero, RingProgramID: zero,
	}, zero)
	return spptest.MustNullifier(t, address, seed, zero)
}

func ZeroCredentialLeaf() registry.CredentialLeaf {
	leaf := registry.CredentialLeaf{
		Credential: registry.Credential{RingID: 0, Member: 0, NullifierPk: 0, ListTag: 0, Aud: [2]frontend.Variable{0, 0}, Eph: [2]frontend.Variable{0, 0}, CtHash: 0},
		Blinding:   0, TreeSlot: 0, StateIndex: 0,
	}
	for i := range leaf.StatePath {
		leaf.StatePath[i] = 0
	}
	return leaf
}

func ZeroCredentialOpening() CredentialOpening {
	opening := CredentialOpening{Present: 0, Leaf: ZeroCredentialLeaf(), Gap: registry.AddressGap{Low: 0, Next: 0, Index: 0}}
	for i := range opening.Gap.Path {
		opening.Gap.Path[i] = 0
	}
	return opening
}

func ZeroCredentialWrite() registry.CredentialWrite {
	write := registry.CredentialWrite{Member: 0, ListSalt: 0, Leaf: ZeroCredentialLeaf(), Address: registry.AddressLeaf{Next: 0, Index: 0}}
	for i := range write.Address.Path {
		write.Address.Path[i] = 0
	}
	return write
}

func (c *Credentials) leaf(t testing.TB, entry CredentialEntry) registry.CredentialLeaf {
	t.Helper()
	address := CredentialAddress(t, c.Owner, c.RingID, entry.Member)
	seed, err := protocol.OutputBlindingSeed(address, big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	blinding, err := protocol.OutputBlinding(address, seed, 0)
	if err != nil {
		t.Fatal(err)
	}
	leaf := ZeroCredentialLeaf()
	leaf.RingID, leaf.Member, leaf.NullifierPk, leaf.ListTag = copied(c.RingID), copied(entry.Member), copied(entry.NullifierPk), copied(entry.ListTag)
	leaf.CtHash, leaf.Blinding = copied(entry.CtHash), blinding
	for i := range leaf.Aud {
		leaf.Aud[i], leaf.Eph[i] = copied(entry.Aud[i]), copied(entry.Eph[i])
	}
	return leaf
}

func (c *Credentials) rebuild(t testing.TB) {
	t.Helper()
	entries := make(map[uint64]*big.Int, len(c.entries))
	for i, entry := range c.entries {
		leaf := c.leaf(t, entry)
		state := spptest.MustHashChain4(t, ringtest.ToBigInts(leaf.Elements(shared.CredentialStateDomain)))
		address := CredentialAddress(t, c.Owner, c.RingID, entry.Member)
		data := ringtest.MustPoseidonHash(t, big.NewInt(0x554e4951), address, state)
		zero := new(big.Int)
		entries[uint64(i)] = spptest.MustUtxoHash(t, protocol.Utxo{
			Domain: big.NewInt(protocol.UtxoDomain), Owner: c.Owner, Asset: shared.SolAssetField, Amount: zero,
			Blinding: ringtest.AsBigInt(leaf.Blinding), DataHash: data, RingDataHash: zero, RingProgramID: zero,
		}, new(big.Int).SetUint64(uint64(c.TreeID)))
	}
	var err error
	c.root, c.proofs, err = protocol.BuildSparseStateTree(entries)
	if err != nil {
		t.Fatal(err)
	}
}
