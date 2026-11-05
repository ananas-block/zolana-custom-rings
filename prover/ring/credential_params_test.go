package ring

import (
	"encoding/json"
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	spp "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestCredentialOpeningAssignmentBindsRingAndPaths(t *testing.T) {
	zero := Field{Int: new(big.Int)}
	field := func(value int64) Field { return Field{Int: big.NewInt(value)} }
	path := func(count int, first int64) []Field {
		values := make([]Field, count)
		for i := range values {
			values[i] = field(first + int64(i))
		}
		return values
	}
	original := CredentialParams{Openings: []CredentialOpeningParams{{
		Present: true,
		CredentialLeafParams: CredentialLeafParams{
			Member: field(2), NullifierPk: field(3), ListTag: field(4),
			Aud: []Field{field(5), field(6)}, Eph: []Field{field(7), field(8)},
			CtHash: field(9), Blinding: field(10), TreeSlot: 1, StateIndex: 11,
			StatePath: path(spp.StateTreeHeight, 12),
		},
		LowValue: zero, LowNext: zero, LowPath: path(spp.NullifierTreeHeight, 100),
	}}}
	params := original.withRingID(field(99))
	var dst policy.CredentialOpening
	if errs := fill(reflect.ValueOf(&dst).Elem(), reflect.ValueOf(params.Openings[0]), "opening"); len(errs) != 0 {
		t.Fatal(errs)
	}
	if dst.Leaf.RingID.(*big.Int).Int64() != 99 || dst.Leaf.Member.(*big.Int).Int64() != 2 {
		t.Fatal("credential identity changed")
	}
	if dst.Leaf.StatePath[31].(*big.Int).Int64() != 43 || dst.Gap.Path[39].(*big.Int).Int64() != 139 {
		t.Fatal("credential paths changed")
	}
	if original.Openings[0].RingID.Int != nil {
		t.Fatal("assignment changed the request")
	}
	params.Openings[0].StatePath = params.Openings[0].StatePath[:spp.StateTreeHeight-1]
	if errs := fill(reflect.ValueOf(&dst).Elem(), reflect.ValueOf(params.Openings[0]), "opening"); len(errs) == 0 {
		t.Fatal("short state path accepted")
	}
	original.Openings[0].Present = false
	if got := original.withRingID(field(99)).Openings[0].RingID; got.Sign() != 0 {
		t.Fatal("absent credential has a ring identity")
	}
}

func TestCredentialDecodeRefusesTrackingFields(t *testing.T) {
	zero := Field{Int: new(big.Int)}
	params := CredentialParams{
		CredentialOwner: zero, AddressRoot: zero,
		StateRoots: []CredentialStateRoot{}, Openings: []CredentialOpeningParams{},
		RowEntries: []uint32{}, OutputEntries: []uint32{},
	}
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	var decoded CredentialParams
	if err := Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trackingRoot", "trackingRecords", "trackingProof", "trackingSubjects"} {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil {
			t.Fatal(err)
		}
		object[name] = json.RawMessage("null")
		mutated, err := json.Marshal(object)
		if err != nil {
			t.Fatal(err)
		}
		if err := Unmarshal(mutated, &decoded); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("old field %s accepted with %v", name, err)
		}
	}
}
