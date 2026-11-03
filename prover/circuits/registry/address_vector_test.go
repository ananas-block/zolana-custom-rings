package registry_test

import (
	"encoding/json"
	"math/big"
	"slices"
	"strconv"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

type decimal uint64

func (d *decimal) UnmarshalJSON(data []byte) error {
	var digits string
	if err := json.Unmarshal(data, &digits); err != nil {
		return err
	}
	value, err := strconv.ParseUint(digits, 10, 64)
	*d = decimal(value)
	return err
}

func (d decimal) big() *big.Int { return new(big.Int).SetUint64(uint64(d)) }

type vectorRecord struct {
	Member              ringtest.Hex   `json:"member"`
	Next                ringtest.Hex   `json:"next"`
	Lists               decimal        `json:"lists"`
	EscrowKey           ringtest.Hex   `json:"escrow_key"`
	MintPolicy          ringtest.Hex   `json:"mint_policy"`
	WithdrawalThreshold decimal        `json:"withdrawal_threshold"`
	Limits              []ringtest.Hex `json:"limits"`
	AddressHash         ringtest.Hex   `json:"address_hash"`
	LeafHash            ringtest.Hex   `json:"leaf_hash"`
}

func (r vectorRecord) record(t *testing.T) ringregistry.Record {
	t.Helper()
	return ringregistry.Record{
		Member: r.Member.Int, Next: r.Next.Int, Lists: r.Lists.big(), EscrowKey: r.EscrowKey.Int, MintPolicy: r.MintPolicy.Int,
		WithdrawalThreshold: r.WithdrawalThreshold.big(), AddressHash: r.AddressHash.Int, AssetLimits: ringregistry.VectorLimits(t, r.Limits),
	}
}

type vectorPair struct {
	AddressRevision decimal      `json:"address_revision"`
	AddressRing     ringtest.Hex `json:"address_ring"`
	CiphertextHash  ringtest.Hex `json:"escrow_ciphertext_hash"`
	NullifierPk     ringtest.Hex `json:"nullifier_pk"`
	View0           ringtest.Hex `json:"view0"`
	View1           ringtest.Hex `json:"view1"`
}

type vectorEntry struct {
	Member              ringtest.Hex   `json:"member"`
	Mask                decimal        `json:"mask"`
	Value               decimal        `json:"value"`
	EscrowKey           ringtest.Hex   `json:"escrow_key"`
	MintPolicy          ringtest.Hex   `json:"mint_policy"`
	WithdrawalThreshold decimal        `json:"withdrawal_threshold"`
	Limits              []ringtest.Hex `json:"limits"`
	AddressHash         ringtest.Hex   `json:"address_hash"`
	EntryHash           ringtest.Hex   `json:"entry_hash"`
}

type vectorWrite struct {
	Exists         bool                    `json:"exists"`
	OldNext        ringtest.Hex            `json:"old_next"`
	OldLists       decimal                 `json:"old_lists"`
	OldEscrow      ringtest.Hex            `json:"old_escrow"`
	OldAddressHash ringtest.Hex            `json:"old_address_hash"`
	Slot           ringregistry.VectorPath `json:"slot"`
	Low            vectorRecord            `json:"low"`
	LowPath        ringregistry.VectorPath `json:"low_path"`
	Pair           *vectorPair             `json:"pair"`
}

type vectorOpening struct {
	Record  vectorRecord            `json:"record"`
	Path    ringregistry.VectorPath `json:"path"`
	Address *struct {
		AddressHash ringtest.Hex `json:"address_hash"`
		RingID      ringtest.Hex `json:"ring_id"`
		Member      ringtest.Hex `json:"member"`
		NullifierPk ringtest.Hex `json:"nullifier_pk"`
		ViewingU    string       `json:"viewing_u"`
		Revision    decimal      `json:"address_revision"`
	} `json:"address"`
	Escrow *struct {
		CiphertextHash ringtest.Hex `json:"ciphertext_hash"`
		NullifierPk    ringtest.Hex `json:"nullifier_pk"`
	} `json:"escrow"`
}

type addressVector struct {
	EmptyRoot ringtest.Hex `json:"empty_root"`
	RingID    ringtest.Hex `json:"ring_id"`
	Steps     []struct {
		Update struct {
			Name          string          `json:"name"`
			OldRoot       ringtest.Hex    `json:"old_root"`
			NewRoot       ringtest.Hex    `json:"new_root"`
			ChainStart    ringtest.Hex    `json:"chain_start"`
			ChainEnd      ringtest.Hex    `json:"chain_end"`
			StatementHash ringtest.Hex    `json:"statement_hash"`
			OldNextIndex  uint64          `json:"old_next_index"`
			NewNextIndex  uint64          `json:"new_next_index"`
			Count         int             `json:"count"`
			Entries       []vectorEntry   `json:"entries"`
			Writes        []vectorWrite   `json:"writes"`
			Openings      []vectorOpening `json:"openings"`
		} `json:"update"`
	} `json:"steps"`
}

// The host replay and the circuit reach every root Rust wrote, escrow beside an address, an address beside an escrow, both in one batch and a rotation included.
func TestAddressRecordVectorReplaysEveryStep(t *testing.T) {
	var v addressVector
	ringtest.ReadVector(t, "registry/address_record.json", &v)
	members := ringregistry.New(t)
	if members.Root().Cmp(v.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", members.Root(), v.EmptyRoot.Int)
	}
	paired := map[string]bool{}
	for _, step := range v.Steps {
		u := step.Update
		t.Run(u.Name, func(t *testing.T) {
			if members.Root().Cmp(u.OldRoot.Int) != 0 {
				t.Fatalf("old root %x, Rust %x", members.Root(), u.OldRoot.Int)
			}
			entries := make([]ringregistry.Entry, len(u.Entries))
			for i, e := range u.Entries {
				entries[i] = ringregistry.Entry{
					Member: e.Member.Int, Mask: e.Mask.big(), Value: e.Value.big(), EscrowKey: e.EscrowKey.Int, MintPolicy: e.MintPolicy.Int,
					WithdrawalThreshold: e.WithdrawalThreshold.big(), AddressHash: e.AddressHash.Int, AssetLimits: ringregistry.VectorLimits(t, e.Limits),
				}
				if hash := entries[i].Hash(t); hash.Cmp(e.EntryHash.Int) != 0 {
					t.Fatalf("entry %d hash %x, Rust %x", i, hash, e.EntryHash.Int)
				}
				if pair := u.Writes[i].Pair; pair != nil {
					entries[i].Pair = &ringregistry.Preimages{NullifierPk: pair.NullifierPk.Int, AddressRing: pair.AddressRing.Int, View0: pair.View0.Int, View1: pair.View1.Int, EscrowCtHash: pair.CiphertextHash.Int, AddressRevision: uint64(pair.AddressRevision)}
					paired[u.Name] = true
				}
			}
			width := registry.ApplyWidths[slices.IndexFunc(registry.ApplyWidths, func(n int) bool { return n >= u.Count })]
			b := applyBatch(t, members, width, u.ChainStart.Int, entries...)
			for name, pair := range map[string][2]*big.Int{
				"new root":       {ringtest.AsBigInt(b.circuit.NewRoot), u.NewRoot.Int},
				"new next index": {ringtest.AsBigInt(b.circuit.NewNextIndex), new(big.Int).SetUint64(u.NewNextIndex)},
				"chain end":      {ringtest.AsBigInt(b.circuit.ChainEnd), u.ChainEnd.Int},
				"statement":      {ringtest.AsBigInt(b.circuit.PublicInputHash), u.StatementHash.Int},
			} {
				if pair[0].Cmp(pair[1]) != 0 {
					t.Fatalf("%s %x, Rust %x", name, pair[0], pair[1])
				}
			}
			// The circuit solves the Rust witness, not the host's.
			for i, w := range u.Writes {
				rust := ringregistry.Write{
					Entry: entries[i], Exists: w.Exists, OldNext: w.OldNext.Int, OldLists: w.OldLists.big(), OldEscrow: w.OldEscrow.Int, OldAddressHash: w.OldAddressHash.Int,
					Slot: w.Slot.Path(t), Low: w.Low.record(t), LowPath: w.LowPath.Path(t),
				}
				old := b.writes[i]
				rust.OldMintPolicy, rust.OldWithdrawalThreshold, rust.OldAssetLimits = old.OldMintPolicy, old.OldWithdrawalThreshold, old.OldAssetLimits
				if !sameWrite(old, rust) {
					t.Fatalf("write %d differs from the Rust witness", i)
				}
				b.circuit.Writes[i] = writeWires(rust)
			}
			if err := solve(t, b.circuit); err != nil {
				t.Fatal(err)
			}
			for i, opening := range u.Openings {
				if hash := opening.Record.record(t).Hash(t); hash.Cmp(opening.Record.LeafHash.Int) != 0 {
					t.Fatalf("opening %d leaf %x, Rust %x", i, hash, opening.Record.LeafHash.Int)
				}
				if root := opening.Path.Path(t).Root(t, opening.Record.LeafHash.Int); root.Cmp(u.NewRoot.Int) != 0 {
					t.Fatalf("opening %d root %x, Rust %x", i, root, u.NewRoot.Int)
				}
				if opening.Address != nil {
					address := ringregistry.Address{RingID: opening.Address.RingID.Int, Member: opening.Address.Member.Int, NullifierPk: opening.Address.NullifierPk.Int, ViewingKey: [32]byte(ringtest.VectorBytes(t, opening.Address.ViewingU, 32)), Revision: uint64(opening.Address.Revision)}
					if hash := address.Hash(t); hash.Cmp(opening.Address.AddressHash.Int) != 0 {
						t.Fatalf("opening %d address hash %x, Rust %x", i, hash, opening.Address.AddressHash.Int)
					}
				}
				if opening.Escrow != nil {
					if key := ringregistry.EscrowKey(t, opening.Escrow.NullifierPk.Int, opening.Escrow.CiphertextHash.Int); key.Cmp(opening.Record.EscrowKey.Int) != 0 {
						t.Fatalf("opening %d escrow key %x, Rust %x", i, key, opening.Record.EscrowKey.Int)
					}
				}
			}
		})
	}
	for _, name := range []string{"an_escrow_write_beside_an_address_proves_both_preimages", "an_address_write_beside_an_escrow_key_proves_both_preimages", "address_and_escrow_in_one_batch_prove_at_the_second_write", "rotation_moves_the_owner_revision_and_replaces_the_hash"} {
		if !paired[name] {
			t.Errorf("the vector has no pair in %s", name)
		}
	}
}

// The sentinel opens the first root of every registry, a differing leaf layout or path shape would miss it.
func TestEmptyRootVectorMatchesTheSentinel(t *testing.T) {
	var v struct {
		EmptyRoot ringtest.Hex `json:"empty_root"`
		Sentinel  vectorRecord `json:"sentinel"`
	}
	ringtest.ReadVector(t, "registry/empty_root.json", &v)
	members := ringregistry.New(t)
	if members.Root().Cmp(v.EmptyRoot.Int) != 0 {
		t.Fatalf("empty root %x, Rust %x", members.Root(), v.EmptyRoot.Int)
	}
	opening := members.Opening(big.NewInt(1))
	if hash := opening.Record.Hash(t); hash.Cmp(v.Sentinel.LeafHash.Int) != 0 || hash.Cmp(v.Sentinel.record(t).Hash(t)) != 0 {
		t.Fatalf("sentinel leaf %x, Rust %x", hash, v.Sentinel.LeafHash.Int)
	}
}

// The domain tag preimage twins AUTHORIZED_ADDRESS in program-libs/interface/src/proof/domain.rs.
func TestAuthorizedAddressDomainIsCRAD(t *testing.T) {
	if got := new(big.Int).SetBytes([]byte("CRAD")); got.Cmp(big.NewInt(shared.AuthorizedAddressDomain)) != 0 {
		t.Fatalf("domain %x", got)
	}
}
