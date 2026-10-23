package indexed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	zolana "github.com/helius-labs/zolana/prover/server/prover/indexed"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

type merkleContext struct {
	Tree     string `json:"tree"`
	TreeType uint16 `json:"treeType"`
}

type stateProof struct {
	Leaf          zolana.Hash   `json:"leaf"`
	MerkleContext merkleContext `json:"merkleContext"`
	Path          []zolana.Hash `json:"path"`
	LeafIndex     uint64        `json:"leafIndex"`
	Root          zolana.Hash   `json:"root"`
	RootSeq       uint64        `json:"rootSeq"`
	RootIndex     uint16        `json:"rootIndex"`
}

type nullifierProof struct {
	Leaf             zolana.Hash   `json:"leaf"`
	MerkleContext    merkleContext `json:"merkleContext"`
	Path             []zolana.Hash `json:"path"`
	LowElement       zolana.Hash   `json:"lowElement"`
	LowElementIndex  uint64        `json:"lowElementIndex"`
	HighElement      zolana.Hash   `json:"highElement"`
	HighElementIndex uint64        `json:"highElementIndex"`
	Root             zolana.Hash   `json:"root"`
	RootSeq          uint64        `json:"rootSeq"`
	RootIndex        uint16        `json:"rootIndex"`
}

type response[T any] struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Proofs []T `json:"proofs"`
}

type call struct {
	Method string `json:"method"`
	Params struct {
		Leaves            []zolana.Hash `json:"leaves"`
		Member            zolana.Hash   `json:"member"`
		ExpectedRoot      zolana.Hash   `json:"expectedRoot"`
		ExpectedNextIndex uint64        `json:"expectedNextIndex"`
	} `json:"params"`
}

func encoded(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func hashOf(t *testing.T, value *big.Int) zolana.Hash {
	t.Helper()
	hash, err := zolana.HashField(value)
	if err != nil {
		t.Fatal(err)
	}
	return hash
}

func hexOf(hash zolana.Hash) string {
	return common.FeHex(new(big.Int).SetBytes(hash[:]))
}

// A nil failure answers with the result.
func indexer(t *testing.T, reply func(call) (result any, failure any)) *zolana.Resolver {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request call
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		body := map[string]any{"jsonrpc": "2.0", "id": request.Method}
		if result, failure := reply(request); failure != nil {
			body["error"] = failure
		} else {
			body["result"] = result
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(encoded(t, body))
	}))
	t.Cleanup(server.Close)
	resolver, err := zolana.NewResolver(zolana.Config{URL: server.URL, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	return resolver
}

// One tree holds leaf 42, nullifiers 100 and 200 sit between 0 and 1000.
func fixture(t *testing.T) (zolana.Tree, response[stateProof], response[nullifierProof]) {
	t.Helper()
	root := func(leaf zolana.Hash, height int) zolana.Hash {
		hash := new(big.Int).SetBytes(leaf[:])
		for range height {
			var err error
			hash, err = transcript.HashFields([]*big.Int{hash, new(big.Int)})
			if err != nil {
				t.Fatal(err)
			}
		}
		return hashOf(t, hash)
	}
	commitment := hashOf(t, big.NewInt(42))
	tree := (zolana.Hash{}).String()
	state := response[stateProof]{Proofs: []stateProof{{
		Leaf: commitment, MerkleContext: merkleContext{Tree: tree, TreeType: 1},
		Path: make([]zolana.Hash, 32), Root: root(commitment, 32), RootIndex: 3,
	}}}
	state.Context.Slot = 10
	leaf, err := transcript.HashFields([]*big.Int{big.NewInt(0), big.NewInt(1000)})
	if err != nil {
		t.Fatal(err)
	}
	exclusion := response[nullifierProof]{Proofs: []nullifierProof{}}
	exclusion.Context.Slot = 10
	for _, value := range []int64{100, 200} {
		exclusion.Proofs = append(exclusion.Proofs, nullifierProof{
			Leaf: hashOf(t, big.NewInt(value)), MerkleContext: merkleContext{Tree: tree, TreeType: 2},
			Path: make([]zolana.Hash, 40), LowElement: hashOf(t, big.NewInt(0)), HighElement: hashOf(t, big.NewInt(1000)),
			Root: root(hashOf(t, leaf), 40), RootIndex: 4,
		})
	}
	return zolana.Tree{Address: tree, ID: 0}, state, exclusion
}

func policyFixture(t *testing.T, enabled bool) (request, response[stateProof], response[nullifierProof]) {
	t.Helper()
	tree, state, exclusion := fixture(t)
	zeroFields := func(count int) []string {
		result := make([]string, count)
		for i := range result {
			result[i] = "0x" + strings.Repeat("00", 32)
		}
		return result
	}
	openings := func(count int) []map[string]any {
		result := make([]map[string]any, count)
		for i := range result {
			result[i] = map[string]any{"domain": "0x" + strings.Repeat("00", 31) + "01", "treeId": "0x" + strings.Repeat("00", 32), "ownerPkHash": "0x" + strings.Repeat("00", 32), "nullifierPk": "0x" + strings.Repeat("00", 32), "asset": "0x" + strings.Repeat("00", 32), "amount": "0x" + strings.Repeat("00", 32), "blinding": "0x" + strings.Repeat("00", 32), "dataHash": "0x" + strings.Repeat("00", 32), "ringDataHash": "0x" + strings.Repeat("00", 32), "ringProgramId": "0x" + strings.Repeat("00", 32)}
		}
		return result
	}
	answers := make([]map[string]any, 10)
	lookups := make([]zolana.Lookup, 10)
	for i := range answers {
		answers[i] = map[string]any{"enabled": false, "treeSlot": 0, "mode": 1, "listId": 1, "state": 1, "absentBranch": 1, "member": "0x" + strings.Repeat("00", 31) + "01", "contentHash": "0x" + strings.Repeat("00", 32), "version": 0, "blinding": "0x" + strings.Repeat("00", 32)}
	}
	if enabled {
		answers[0]["enabled"], answers[0]["absentBranch"] = true, 2
		lookups[0] = zolana.Lookup{TreeSlot: 0, Commitment: &state.Proofs[0].Leaf, Nullifier: &exclusion.Proofs[0].Leaf}
	}
	sources, velocity := make([]map[string]any, 8), make([]map[string]any, 8)
	for i := range sources {
		sources[i] = map[string]any{"listId": 0, "ownerHash": "0x" + strings.Repeat("00", 32)}
	}
	for i := range velocity {
		velocity[i] = map[string]any{"asset": "0x" + strings.Repeat("00", 32), "cap": "0x" + strings.Repeat("00", 32), "cosignAbove": "0x" + strings.Repeat("00", 32)}
	}
	rules := make([]string, 16)
	for i := range rules {
		rules[i] = "0x" + strings.Repeat("00", 32)
	}
	prepared := map[string]any{
		"circuitType":   ring.CustomRingPolicyCircuitType,
		"privateTxHash": "0x" + strings.Repeat("00", 31) + "01", "txViewingSk": "0x" + strings.Repeat("00", 31) + "41", "ephSk": "0x" + strings.Repeat("00", 31) + "02",
		"auditorPk": "0x09" + strings.Repeat("00", 31),
		"salt":      "0x" + strings.Repeat("00", 16), "nIn": 1, "nOut": 1, "inputs": openings(5), "outputs": openings(4),
		"addressChain": "0x" + strings.Repeat("00", 32), "externalDataHash": "0x" + strings.Repeat("00", 32), "privateTxBlinding": "0x" + strings.Repeat("00", 32), "sources": sources, "policyLen": 0, "ruleEnc": rules,
		"inlineAssets": zeroFields(8), "inlineLimits": zeroFields(8), "inlineCount": 0, "windowSlots": 0, "velocity": velocity, "velocityCount": 0,
		"addressTreeId": "0x" + strings.Repeat("00", 32), "ringId": "0x" + strings.Repeat("00", 31) + "01", "namespaceOwnerHash": "0x" + strings.Repeat("00", 31) + "01", "windowIndex": 0, "approvalRequired": false, "keyEscrow": false, "keyRegistryRoot": "0x" + strings.Repeat("00", 32),
		"record": map[string]any{"version": 0, "window": 0, "commitment": "0x" + strings.Repeat("00", 32), "salt": "0x" + strings.Repeat("00", 32), "assets": zeroFields(8), "spent": zeroFields(8), "nextSalt": "0x" + strings.Repeat("00", 32)}, "answers": answers,
	}
	tree.Fallback = &common.ResolvedTree{Tree: tree.Address, ID: tree.ID, UtxoRoot: hexOf(state.Proofs[0].Root), NullifierRoot: hexOf(exclusion.Proofs[0].Root), UtxoRootIndex: state.Proofs[0].RootIndex, NullifierRootIndex: exclusion.Proofs[0].RootIndex}
	return request{Request: zolana.Request{CircuitType: ring.CustomRingPolicyCircuitType, Prepared: encoded(t, prepared), Trees: []zolana.Tree{tree}, Inputs: lookups, PublicInputs: zeroFields(19)}}, state, exclusion
}

func TestPolicyResolvesOnlyEnabledFacts(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		request, state, exclusion := policyFixture(t, enabled)
		exclusion.Proofs = exclusion.Proofs[:1]
		resolver := indexer(t, func(request call) (any, any) {
			if !enabled {
				t.Error("disabled facts queried indexer")
			}
			if len(request.Params.Leaves) != 1 {
				t.Error("unexpected enabled fact count")
			}
			switch request.Method {
			case "getMerkleProofs":
				return state, nil
			case "getNonInclusionProofs":
				return exclusion, nil
			}
			t.Error("unexpected indexer method")
			return nil, map[string]any{"code": -32601}
		})
		resolved, err := resolver.Resolve(context.Background(), encoded(t, request))
		if err != nil {
			t.Fatal(err)
		}
		var params ring.PolicyParameters
		if err := json.Unmarshal(resolved.Payload, &params); err != nil {
			t.Fatal(err)
		}
		if common.FeHex(params.PublicInputHash) != resolved.Resolution.PublicInputHash {
			t.Fatal("policy statement mismatch")
		}
		if enabled && params.ListFacts[0].Low.Cmp(new(big.Int).SetBytes(exclusion.Proofs[0].LowElement[:])) != 0 {
			t.Fatal("unresolved exclusion")
		}
	}
}

func TestPolicyRejectsNullFactsInEveryWrapper(t *testing.T) {
	for _, circuit := range []common.CircuitType{ring.CustomRingPolicyCircuitType, ring.CustomRingDelegatePolicyCircuitType, ring.CustomRingCompressedPolicyCircuitType} {
		t.Run(string(circuit), func(t *testing.T) {
			request, _, _ := policyFixture(t, false)
			var base map[string]any
			if err := json.Unmarshal(request.Prepared, &base); err != nil {
				t.Fatal(err)
			}
			base["answers"].([]any)[0] = nil
			request.CircuitType = circuit
			if circuit == ring.CustomRingPolicyCircuitType {
				request.Prepared = encoded(t, base)
			} else {
				request.Prepared = encoded(t, map[string]any{"circuitType": circuit, "policy": base, "transactionSalt": "0x" + strings.Repeat("00", 16)})
			}
			if circuit == ring.CustomRingCompressedPolicyCircuitType {
				request.PublicInputs = append(request.PublicInputs, "0x0")
			}
			if zolana.Validate(encoded(t, request)) == nil {
				t.Fatal("null fact accepted")
			}
		})
	}
}

func TestPolicyRegistryBindsOwnerKeyAndAnchor(t *testing.T) {
	request, _, _ := policyFixture(t, false)
	var base map[string]any
	if err := json.Unmarshal(request.Prepared, &base); err != nil {
		t.Fatal(err)
	}
	output := base["outputs"].([]any)[0].(map[string]any)
	output["domain"] = common.ToHex(big.NewInt(shared.UtxoDomain))
	output["ownerPkHash"], output["nullifierPk"] = common.ToHex(big.NewInt(5)), common.ToHex(big.NewInt(6))
	ciphertext := bytes.Repeat([]byte{7}, 32)
	ctHash, _ := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(ciphertext[:31]), new(big.Int).SetBytes(ciphertext[31:])})
	keyHash, _ := transcript.HashFields([]*big.Int{big.NewInt(6), ctHash})
	leaf, _ := transcript.HashFields([]*big.Int{big.NewInt(5), big.NewInt(8), keyHash})
	root := leaf
	path := make([]zolana.Hash, 40)
	for i := range path {
		pair := []*big.Int{root, new(big.Int)}
		if i == 0 {
			pair[0], pair[1] = pair[1], pair[0]
		}
		root, _ = transcript.HashFields(pair)
	}
	rootHash := hashOf(t, root)
	member := hashOf(t, big.NewInt(5))
	next := hashOf(t, big.NewInt(8))
	request.Registry = &RegistryRequest{Ring: zolana.Hash{}, Root: rootHash, NextIndex: 2}
	base["keyEscrow"], base["keyRegistryRoot"] = true, common.ToHex(root)
	request.Prepared = encoded(t, base)
	for _, circuit := range []common.CircuitType{ring.CustomRingPolicyCircuitType, ring.CustomRingDepositCircuitType} {
		for _, mutation := range []string{"", "owner", "root", "count", "index", "path", "ciphertext", "nullifier", "stale", "unregistered"} {
			t.Run(string(circuit)+"/"+mutation, func(t *testing.T) {
				entry := registryEntry{Root: rootHash, Member: member, Next: next, NextIndex: 2, Index: 1, Ciphertext: append([]byte{}, ciphertext...), Proof: append([]zolana.Hash{}, path...)}
				switch mutation {
				case "owner":
					entry.Member[31]++
				case "root":
					entry.Root[31]++
				case "count":
					entry.NextIndex++
				case "index":
					entry.Index = 0
				case "path":
					entry.Proof[1][31]++
				case "ciphertext":
					entry.Ciphertext[0]++
				}
				current := request
				if mutation == "nullifier" {
					output["nullifierPk"] = common.ToHex(big.NewInt(7))
					current.Prepared = encoded(t, base)
					output["nullifierPk"] = common.ToHex(big.NewInt(6))
				}
				if circuit == ring.CustomRingDepositCircuitType {
					var policy map[string]any
					if err := json.Unmarshal(current.Prepared, &policy); err != nil {
						t.Fatal(err)
					}
					output := policy["outputs"].([]any)[0].(map[string]any)
					column := func(first any) []any {
						values := make([]any, 8)
						for i := range values {
							values[i] = common.ToHex(new(big.Int))
						}
						values[0] = first
						return values
					}
					current.CircuitType = circuit
					current.Trees = nil
					current.Inputs = nil
					current.PublicInputs = []string{"0x0"}
					current.Prepared = encoded(t, map[string]any{"circuitType": circuit, "publicInputHash": common.ToHex(new(big.Int)), "contextHash": common.ToHex(new(big.Int)), "count": 1, "ownerPkHashes": column(output["ownerPkHash"]), "nullifierPks": column(output["nullifierPk"]), "blindings": column(common.ToHex(big.NewInt(1))), "keyEscrow": true, "keyRegistryRoot": base["keyRegistryRoot"], "ephSk": base["ephSk"], "auditorPk": base["auditorPk"]})
				}
				if mutation == "stale" {
					current.MinContextSlot = 1
				}
				calls := 0
				resolver := indexer(t, func(query call) (any, any) {
					calls++
					if query.Method != "getRingKeyRegistryEntry" || query.Params.Member != member || query.Params.ExpectedRoot != rootHash || query.Params.ExpectedNextIndex != 2 {
						t.Error("registry query mismatch")
					}
					if mutation == "unregistered" {
						return nil, map[string]any{"code": -32072}
					}
					return entry, nil
				})
				resolved, err := resolver.Resolve(context.Background(), encoded(t, current))
				if (err == nil) != (mutation == "") {
					t.Fatalf("unexpected registry validation result %v", err)
				}
				var unregistered *zolana.Rejection
				if slices.Contains([]string{"path", "ciphertext", "nullifier", "unregistered"}, mutation) != errors.As(err, &unregistered) || (unregistered != nil && unregistered.Detail["member"] != member.String()) {
					t.Fatalf("unexpected unregistered member classification %v", err)
				}
				if mutation == "stale" {
					if !errors.Is(err, zolana.ErrIndexerNotReady) {
						t.Fatalf("slot lag is not retryable %v", err)
					}
					entry.Context.Slot = current.MinContextSlot
					if _, err := resolver.Resolve(context.Background(), encoded(t, current)); err != nil || calls != 2 {
						t.Fatalf("fresh membership rejected %v", err)
					}
				}
				if mutation == "" && circuit == ring.CustomRingDepositCircuitType {
					var params ring.DepositParameters
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Keys[0] == nil || params.Keys[0].Index != 1 || params.Keys[0].CtHash.Cmp(ctHash) != 0 || calls != 1 || resolved.Resolution.PublicInputHash != common.FeHex(params.PublicInputHash) {
						t.Fatal("unresolved deposit membership")
					}
					for _, key := range params.Keys[1:] {
						if key != nil {
							t.Fatal("nonzero deposit padding")
						}
					}
				}
				if mutation == "" && circuit == ring.CustomRingPolicyCircuitType {
					var params ring.PolicyParameters
					if err := json.Unmarshal(resolved.Payload, &params); err != nil {
						t.Fatal(err)
					}
					if params.Outputs[0].Key == nil || params.Outputs[0].Key.Index != 1 || params.Outputs[0].Key.CtHash.Cmp(ctHash) != 0 || calls != 1 {
						t.Fatal("unresolved registry key")
					}
				}
			})
		}
	}
}

func TestRegistryProjectionLagRemainsRetryable(t *testing.T) {
	request, _, _ := policyFixture(t, false)
	request.Registry = &RegistryRequest{NextIndex: 1}
	for _, code := range []int{-32070, -32071, -32603} {
		resolver := indexer(t, func(call) (any, any) {
			return nil, map[string]any{"code": code, "message": "private upstream details"}
		})
		_, err := registryKey(context.Background(), resolver, request, nil, big.NewInt(5), big.NewInt(6))
		if errors.Is(err, zolana.ErrIndexerNotReady) != (code != -32603) {
			t.Fatalf("unexpected retry classification for %d", code)
		}
		if strings.Contains(err.Error(), "private") {
			t.Fatal("upstream details leaked")
		}
	}
}
