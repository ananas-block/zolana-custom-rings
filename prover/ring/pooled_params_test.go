package ring

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const pooledMemberLabel common.CircuitType = "test-policy-member-v3"
const pooledDelegateLabel common.CircuitType = "test-policy-delegate-v3"

func TestPooledRequestsDecodeAndSolve(t *testing.T) {
	for _, own := range []bool{false, true} {
		for _, anonymous := range []bool{false, true} {
			w := ringpolicy.Confidential()
			w.OwnOnly, w.Anonymous = own, anonymous
			w.WithdrawalCapacity = 2
			w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 1}}
			if !own {
				w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
				w.Curator = w.Own
			}
			t.Run(fmt.Sprintf("member-own%v-anonymous%v", own, anonymous), func(t *testing.T) {
				b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
				shape := policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2, Withdrawals: 2, OwnOnly: own}}
				params := requestOf[MemberPolicyV3Params](t, pooledMemberLabel, b.Assignment())
				request, err := NewMemberPolicyV3Request(pooledMemberLabel, shape)
				if err != nil {
					t.Fatal(err)
				}
				requirePooledRequestSolved(t, request, mustMarshal(t, params), func() (frontend.Circuit, error) { return policy.NewMemberPolicyCircuitV3(shape) })
			})
		}
		for _, width := range []int{2, 4} {
			t.Run(fmt.Sprintf("delegate-%d-own%v", width, own), func(t *testing.T) {
				w := ringpolicy.Delegate(transaction.Shape{NInputs: width, NOutputs: width})
				w.OwnOnly = own
				if !own {
					w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
					w.Curator = w.Own
				}
				b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
				shape := policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: w.Shape, OwnOnly: own}}
				params := requestOf[DelegatePolicyV3Params](t, pooledDelegateLabel, b.Assignment())
				request, err := NewDelegatePolicyV3Request(pooledDelegateLabel, shape)
				if err != nil {
					t.Fatal(err)
				}
				requirePooledRequestSolved(t, request, mustMarshal(t, params), func() (frontend.Circuit, error) { return policy.NewDelegatePolicyCircuitV3(shape) })
			})
		}
	}
}

func requirePooledRequestSolved(t *testing.T, request common.ExtensionRequest, payload []byte, build func() (frontend.Circuit, error)) {
	t.Helper()
	if err := json.Unmarshal(payload, request); err != nil {
		t.Fatal(err)
	}
	assignment, err := request.Assignment()
	if err != nil {
		t.Fatal(err)
	}
	circuit, err := build()
	if err != nil {
		t.Fatal(err)
	}
	cs := ringkey.Compile(t, circuit)
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

func pooledMemberPayload(t testing.TB) []byte {
	t.Helper()
	w := ringpolicy.Confidential()
	w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
	w.Curator = w.Own
	b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
	return mustMarshal(t, requestOf[MemberPolicyV3Params](t, pooledMemberLabel, b.Assignment()))
}

func decodePooledMember(payload []byte) (frontend.Circuit, error) {
	request, err := NewMemberPolicyV3Request(pooledMemberLabel, policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2}})
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(payload, request); err != nil {
		return nil, err
	}
	return request.Assignment()
}

func TestPooledRequestsRejectMalformedPayloads(t *testing.T) {
	payload := pooledMemberPayload(t)
	record := func(m map[string]any) map[string]any { return m["ownRecords"].([]any)[0].(map[string]any) }
	subject := func(m map[string]any) map[string]any { return m["ownSubjects"].([]any)[0].(map[string]any) }
	entry := func(m map[string]any) map[string]any { return m["senderEntry"].(map[string]any) }
	proof := func(m map[string]any) map[string]any { return m["ownProof"].(map[string]any) }
	path := func(m map[string]any) map[string]any { return proof(m)["paths"].([]any)[0].(map[string]any) }
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   string
	}{
		{"unknown field", func(m map[string]any) { m["version"] = 3 }, "unknown field"},
		{"unknown record field", func(m map[string]any) { record(m)["present"] = true }, "unknown field"},
		{"missing common field", func(m map[string]any) { delete(m, "privateTxHash") }, "missing field"},
		{"missing record field", func(m map[string]any) { delete(record(m), "next") }, "missing field"},
		{"missing subject index", func(m map[string]any) { delete(subject(m), "recordIndex") }, "missing field"},
		{"missing curator reference", func(m map[string]any) { delete(entry(m), "curator") }, "missing field"},
		{"null record field", func(m map[string]any) { record(m)["member"] = nil }, "missing"},
		{"noncanonical member", func(m map[string]any) { record(m)["member"] = "0x01" }, "not canonical"},
		{"modulus member", func(m map[string]any) { record(m)["member"] = "0x" + ecc.BN254.ScalarField().Text(16) }, "not canonical"},
		{"negative subject index", func(m map[string]any) { subject(m)["recordIndex"] = -1 }, "uint32"},
		{"fractional subject index", func(m map[string]any) { subject(m)["recordIndex"] = 0.5 }, "uint32"},
		{"record index outside pool", func(m map[string]any) { subject(m)["recordIndex"] = len(m["ownRecords"].([]any)) }, "record index"},
		{"subject index outside pool", func(m map[string]any) { entry(m)["own"] = len(m["ownSubjects"].([]any)) }, "subject index"},
		{"curator index outside pool", func(m map[string]any) { entry(m)["curator"] = []any{len(m["curatorSubjects"].([]any))} }, "subject index"},
		{"public asset index outside pool", func(m map[string]any) { m["publicAssetEntries"].([]any)[0] = len(m["ownSubjects"].([]any)) }, "subject index"},
		{"path index outside tree", func(m map[string]any) { path(m)["index"] = registry.Capacity }, "path index"},
		{"short canopy", func(m map[string]any) { proof(m)["canopy"] = proof(m)["canopy"].([]any)[1:] }, "expected"},
		{"short path", func(m map[string]any) { path(m)["siblings"] = path(m)["siblings"].([]any)[1:] }, "expected"},
		{"short sibling row", func(m map[string]any) { rows := path(m)["siblings"].([]any); rows[0] = rows[0].([]any)[1:] }, "expected"},
		{"wrong circuit label", func(m map[string]any) { m["circuitType"] = pooledDelegateLabel }, "request on"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			tc.mutate(raw)
			if _, err := decodePooledMember(mustMarshal(t, raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %q, got %v", tc.want, err)
			}
		})
	}
	if _, err := decodePooledMember(append(payload, []byte("{}")...)); err == nil {
		t.Fatal("trailing payload accepted")
	}
	duplicate := append([]byte(`{"circuitType":"`+string(pooledMemberLabel)+`",`), payload[1:]...)
	if _, err := decodePooledMember(duplicate); err == nil || !strings.Contains(err.Error(), "repeated field") {
		t.Fatalf("duplicate header accepted %v", err)
	}
}

func TestPooledRequestsRequireExplicitShape(t *testing.T) {
	if _, err := NewMemberPolicyV3Request("", policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2}}); err == nil {
		t.Fatal("empty member circuit label accepted")
	}
	if _, err := NewDelegatePolicyV3Request("", policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: transaction.Shape{NInputs: 2, NOutputs: 2}}}); err == nil {
		t.Fatal("empty delegate circuit label accepted")
	}
	if _, err := NewMemberPolicyV3Request(pooledMemberLabel, policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 3}}); err == nil {
		t.Fatal("invalid member shape accepted")
	}
	if _, err := NewDelegatePolicyV3Request(pooledDelegateLabel, policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: transaction.Shape{NInputs: 0, NOutputs: 2}}}); err == nil {
		t.Fatal("invalid delegate shape accepted")
	}
	if _, registered := common.LookupExtension(pooledMemberLabel); registered {
		t.Fatal("member builder registered a circuit")
	}
	if _, registered := common.LookupExtension(pooledDelegateLabel); registered {
		t.Fatal("delegate builder registered a circuit")
	}
}

func TestPooledOwnRequestsRequireEmptyCuratorReferences(t *testing.T) {
	w := ringpolicy.Confidential()
	w.OwnOnly = true
	b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
	params := requestOf[MemberPolicyV3Params](t, pooledMemberLabel, b.Assignment())
	params.SenderEntry.Curator = []uint32{0}
	request, err := NewMemberPolicyV3Request(pooledMemberLabel, policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2, OwnOnly: true}})
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(mustMarshal(t, params), request); err != nil {
		t.Fatal(err)
	}
	if _, err = request.Assignment(); err == nil {
		t.Fatal("own key accepted a curator reference")
	}
}
