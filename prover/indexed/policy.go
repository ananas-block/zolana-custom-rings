package indexed

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	zolana "github.com/helius-labs/zolana/prover/server/prover/indexed"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

var policyCircuits = []common.CircuitType{ring.CustomRingPolicyCircuitType, ring.CustomRingCompressedPolicyCircuitType, ring.CustomRingDelegatePolicyCircuitType}

func decodePolicyRequest(data []byte) (zolana.Resolution, error) {
	var request request
	if err := zolana.DecodeEnvelope(data, &request); err != nil {
		return nil, err
	}
	publicInputs := 19
	if request.CircuitType == ring.CustomRingCompressedPolicyCircuitType {
		publicInputs = 20
	}
	if err := request.Check(zolana.Limits{Trees: 5, PublicInputs: publicInputs}); err != nil {
		return nil, err
	}
	prepared, err := decodePolicy(request)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r *zolana.Resolver) (*zolana.Resolved, error) {
		return r.ResolvePrepared(ctx, request.Request, prepared)
	}, nil
}

// The policy statement folds the tree hash in after the first public input.
func policyStatement(public []*big.Int, trees *big.Int) (*big.Int, error) {
	value := public[0]
	for _, field := range append([]*big.Int{trees}, public[1:]...) {
		var err error
		if value, err = transcript.HashFields([]*big.Int{value, field}); err != nil {
			return nil, err
		}
	}
	return value, nil
}

type policyTarget struct {
	fact                       *ring.ListFact
	state, exclusion           []*big.Int
	stateIndex, exclusionIndex *big.Int
}

type resolvedPolicy struct {
	base    *ring.PolicyParameters
	wrapped json.Marshaler
	targets []policyTarget
	slots   []common.TreeSlotParams
}

func (p *resolvedPolicy) MarshalJSON() ([]byte, error) {
	for _, target := range p.targets {
		copy(target.fact.StatePathElements[:], target.state)
		copy(target.fact.NfPathElements[:], target.exclusion)
		target.fact.StatePathIndex = target.stateIndex.Uint64()
		target.fact.NfPathIndex = target.exclusionIndex.Uint64()
	}
	for i, slot := range p.slots {
		p.base.TreeSlots[i] = ring.TreeSlot{ID: slot.ID, UtxoRoot: slot.UtxoRoot, NullifierRoot: slot.NullifierRoot}
	}
	return p.wrapped.MarshalJSON()
}

func decodePolicy(request request) (*zolana.Prepared, error) {
	var outer map[string]json.RawMessage
	if json.Unmarshal(request.Prepared, &outer) != nil {
		return nil, fmt.Errorf("invalid prepared policy")
	}
	var base map[string]json.RawMessage
	if request.CircuitType == ring.CustomRingPolicyCircuitType {
		base = outer
	} else {
		if json.Unmarshal(outer["policy"], &base) != nil {
			return nil, fmt.Errorf("missing prepared policy")
		}
	}
	if base["treeSlots"] != nil || base["publicInputHash"] != nil {
		return nil, fmt.Errorf("prepared policy contains resolved roots")
	}
	var facts []map[string]json.RawMessage
	if json.Unmarshal(base["answers"], &facts) != nil || len(facts) != 10 || len(request.Inputs) != len(facts) {
		return nil, fmt.Errorf("invalid prepared fact count")
	}
	for _, fact := range facts {
		if fact == nil {
			return nil, fmt.Errorf("invalid prepared fact")
		}
		for field, height := range map[string]int{"nfPathElements": 40, "statePathElements": 32} {
			if fact[field] != nil {
				return nil, fmt.Errorf("prepared policy contains paths")
			}
			nodes := make([]string, height)
			for i := range nodes {
				nodes[i] = common.ToHex(new(big.Int))
			}
			fact[field], _ = json.Marshal(nodes)
		}
		for _, name := range []string{"nfPathIndex", "statePathIndex", "low", "next"} {
			if fact[name] != nil {
				return nil, fmt.Errorf("prepared policy contains proof data")
			}
		}
		fact["nfPathIndex"], fact["statePathIndex"] = json.RawMessage("0"), json.RawMessage("0")
		fact["low"], _ = json.Marshal(common.ToHex(new(big.Int)))
		fact["next"] = fact["low"]
	}
	if err := prepareRegistry(base, request.Registry); err != nil {
		return nil, err
	}
	slots := make([]common.TreeSlotParams, len(request.Trees))
	for i, tree := range request.Trees {
		fallback := tree.Fallback
		if fallback == nil || fallback.Tree != tree.Address || fallback.ID != tree.ID || fallback.UtxoRootIndex >= 500 || fallback.NullifierRootIndex >= 100 {
			return nil, fmt.Errorf("invalid policy fallback roots")
		}
		state, err := common.FeFromHex(fallback.UtxoRoot)
		if err != nil || state.Sign() == 0 {
			return nil, fmt.Errorf("invalid policy state root")
		}
		exclusion, err := common.FeFromHex(fallback.NullifierRoot)
		if err != nil {
			return nil, err
		}
		if _, err := zolana.HashField(state); err != nil {
			return nil, err
		}
		if _, err := zolana.HashField(exclusion); err != nil {
			return nil, err
		}
		slots[i] = common.TreeSlotParams{ID: new(big.Int).SetUint64(uint64(tree.ID)), UtxoRoot: state, NullifierRoot: exclusion}
	}
	base["treeSlots"], _ = json.Marshal(common.TreeSlotsToJSON(slots))
	base["publicInputHash"], _ = json.Marshal(common.ToHex(new(big.Int)))
	base["answers"], _ = json.Marshal(facts)
	if request.CircuitType != ring.CustomRingPolicyCircuitType {
		outer["policy"], _ = json.Marshal(base)
	}
	data, err := json.Marshal(outer)
	if err != nil {
		return nil, err
	}
	p := &resolvedPolicy{}
	switch request.CircuitType {
	case ring.CustomRingPolicyCircuitType:
		value := &ring.PolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = value, value
	case ring.CustomRingCompressedPolicyCircuitType:
		value := &ring.CompressedPolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = &value.Base, value
	case ring.CustomRingDelegatePolicyCircuitType:
		value := &ring.DelegatePolicyParameters{}
		if err = json.Unmarshal(data, value); err != nil {
			return nil, err
		}
		p.base, p.wrapped = &value.Policy, value
	}
	p.targets = make([]policyTarget, len(facts))
	inputs := make([]zolana.Input, len(facts))
	for i := range p.targets {
		fact, lookup := &p.base.ListFacts[i], request.Inputs[i]
		if int(lookup.TreeSlot) >= len(request.Trees) || fact.TreeSlot != lookup.TreeSlot || fact.Enabled != (lookup.Nullifier != nil) || (fact.Enabled && (fact.AbsentBranch == 2) != (lookup.Commitment != nil)) || (!fact.Enabled && lookup.Commitment != nil) {
			return nil, fmt.Errorf("policy lookup mismatch")
		}
		target := &p.targets[i]
		*target = policyTarget{fact: fact, stateIndex: new(big.Int), exclusionIndex: new(big.Int)}
		nullifier := new(big.Int)
		if lookup.Nullifier != nil {
			nullifier, err = lookup.Nullifier.Field()
			if err != nil {
				return nil, err
			}
		}
		inputs[i] = zolana.Input{Nullifier: nullifier, Disabled: !fact.Enabled,
			State: &target.state, Exclusion: &target.exclusion, StateIndex: &target.stateIndex, ExclusionIndex: &target.exclusionIndex, Low: &fact.Low, High: &fact.Next}
	}
	return &zolana.Prepared{
		Value: p, Inputs: inputs, Slots: &p.slots, Hash: &p.base.PublicInputHash, EmptyTrees: true, Statement: policyStatement,
		Fetch: func(ctx context.Context, r *zolana.Resolver) error { return resolvePolicyRegistry(ctx, r, request, p) },
	}, nil
}
