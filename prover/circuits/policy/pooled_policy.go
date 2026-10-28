package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type RecordPoolShape struct {
	Own, Curator                 int
	OwnSubjects, CuratorSubjects int
}

type PoolEntry struct {
	Own     frontend.Variable
	Curator []frontend.Variable
}

type PolicyV3 struct {
	PolicyInputs
	OwnRecords         []registry.Record
	CuratorRecords     []registry.Record
	OwnProof           registry.SharedQuadProof
	CuratorProof       registry.SharedQuadProof
	OwnSubjects        []PoolSubject
	CuratorSubjects    []PoolSubject
	SenderEntry        PoolEntry
	OwnerEntries       []PoolEntry
	AssetEntries       []PoolEntry
	PublicAssetEntries [transaction.NPublicSlots]frontend.Variable
}

type MemberShapeV3 struct {
	MemberShape
	Records RecordPoolShape
}

type DelegateShapeV3 struct {
	DelegateShape
	Records RecordPoolShape
}

type MemberPolicyCircuitV3 struct {
	MemberPolicyValues
	PolicyV3
}

type DelegatePolicyCircuitV3 struct {
	DelegatePolicyValues
	PolicyV3
}

type pooledResolver struct {
	policy       *PolicyV3
	own, curator subjectPool
}

func NewMemberPolicyCircuitV3(shape MemberShapeV3) (*MemberPolicyCircuitV3, error) {
	legacy, err := NewMemberPolicyCircuitWith(shape.MemberShape)
	if err != nil {
		return nil, err
	}
	p, err := newPolicyV3(legacy.PolicyInputs, shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	return &MemberPolicyCircuitV3{PolicyV3: p}, nil
}

func NewDelegatePolicyCircuitV3(shape DelegateShapeV3) (*DelegatePolicyCircuitV3, error) {
	legacy, err := NewDelegatePolicyCircuitWith(shape.DelegateShape)
	if err != nil {
		return nil, err
	}
	p, err := newPolicyV3(legacy.PolicyInputs, shape.Records, 0)
	if err != nil {
		return nil, err
	}
	return &DelegatePolicyCircuitV3{DelegatePolicyValues: legacy.DelegatePolicyValues, PolicyV3: p}, nil
}

func (c *MemberPolicyCircuitV3) Define(api frontend.API) error {
	if err := c.PolicyV3.validate(transaction.NPublicSlots); err != nil {
		return err
	}
	legacy := MemberPolicyCircuit{MemberPolicyValues: c.MemberPolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return legacy.define(api, &pooledResolver{policy: &c.PolicyV3}, 3)
}

func (c *MemberPolicyCircuitV3) Statement() []frontend.Variable {
	legacy := MemberPolicyCircuit{MemberPolicyValues: c.MemberPolicyValues}
	return c.statementVersion(legacy.rail(), 3)
}

func (c *DelegatePolicyCircuitV3) Define(api frontend.API) error {
	if len(c.Inputs) == 0 {
		return fmt.Errorf("policy requires a delegate input")
	}
	if err := c.PolicyV3.validate(0); err != nil {
		return err
	}
	legacy := DelegatePolicyCircuit{DelegatePolicyValues: c.DelegatePolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return legacy.define(api, &pooledResolver{policy: &c.PolicyV3}, 3)
}

func (c *DelegatePolicyCircuitV3) Statement() []frontend.Variable {
	return c.statementVersion(delegateRail, 3)
}

func newPolicyV3(inputs PolicyInputs, capacity RecordPoolShape, publicAssets int) (PolicyV3, error) {
	payments := len(inputs.Outputs) + len(inputs.Withdrawals)
	limits := inputs.recordCapacity(publicAssets)
	capacity = capacity.withDefaults(limits)
	if err := capacity.validate(limits); err != nil {
		return PolicyV3{}, err
	}
	p := PolicyV3{OwnSubjects: make([]PoolSubject, capacity.OwnSubjects), CuratorSubjects: make([]PoolSubject, capacity.CuratorSubjects), PolicyInputs: inputs, OwnRecords: make([]registry.Record, capacity.Own), CuratorRecords: make([]registry.Record, capacity.Curator), SenderEntry: newPoolEntry(inputs.OwnOnly), OwnerEntries: make([]PoolEntry, payments), AssetEntries: make([]PoolEntry, payments)}
	for i := range p.OwnerEntries {
		p.OwnerEntries[i], p.AssetEntries[i] = newPoolEntry(inputs.OwnOnly), newPoolEntry(inputs.OwnOnly)
	}

	var err error
	p.OwnProof, err = registry.NewSharedQuadProof(capacity.Own)
	if err != nil {
		return PolicyV3{}, err
	}
	if !inputs.OwnOnly {
		p.CuratorProof, err = registry.NewSharedQuadProof(capacity.Curator)
		if err != nil {
			return PolicyV3{}, err
		}
	}
	return p, p.validate(publicAssets)
}

func (p *PolicyV3) validate(publicAssets int) error {
	payments := len(p.Outputs) + len(p.Withdrawals)
	if len(p.Outputs) == 0 || len(p.OwnerEntries) != payments || len(p.AssetEntries) != payments {
		return fmt.Errorf("policy requires owner and asset references for every payment")
	}
	capacity := RecordPoolShape{Own: len(p.OwnRecords), Curator: len(p.CuratorRecords), OwnSubjects: len(p.OwnSubjects), CuratorSubjects: len(p.CuratorSubjects)}
	if err := capacity.validate(p.recordCapacity(publicAssets)); err != nil {
		return err
	}
	entries := append([]PoolEntry{p.SenderEntry}, p.OwnerEntries...)
	entries = append(entries, p.AssetEntries...)
	for _, entry := range entries {
		if err := entry.validate(p.OwnOnly); err != nil {
			return err
		}
	}
	return nil
}

func newPoolEntry(ownOnly bool) PoolEntry {
	entry := PoolEntry{}
	if !ownOnly {
		entry.Curator = make([]frontend.Variable, 1)
	}
	return entry
}

func (r *pooledResolver) resolveSubjects(api frontend.API, t tableView, sender frontend.Variable, outputs []utxoView) (subjects, error) {
	p := r.policy
	own, err := openRecordPool(api, 1, p.OwnRoot, p.OwnRecords, p.OwnProof)
	if err != nil {
		return subjects{}, err
	}
	r.own = openSubjectPool(api, own, p.OwnSubjects)
	if !p.OwnOnly {
		curator, err := openRecordPool(api, t.sources.anyForeign, p.CuratorRoot, p.CuratorRecords, p.CuratorProof)
		if err != nil {
			return subjects{}, err
		}
		r.curator = openSubjectPool(api, curator, p.CuratorSubjects)
	}
	s := subjects{owners: make([]subjectView, len(outputs)), assets: make([]subjectView, len(outputs)), mintPolicies: make([]mintPolicyWires, len(outputs))}
	s.sender, _ = r.resolve(api, t.sources, p.SenderEntry, 1, sender)
	for i, out := range outputs {
		s.owners[i], _ = r.resolve(api, t.sources, p.OwnerEntries[i], out.utxo, out.ownerPkHash)
		s.assets[i], s.mintPolicies[i] = r.resolve(api, t.sources, p.AssetEntries[i], out.utxo, out.asset)
	}
	return s, nil
}

func (r *pooledResolver) resolve(api frontend.API, sources sourceView, entry PoolEntry, active, member frontend.Variable) (subjectView, mintPolicyWires) {
	own := r.own.resolve(api, recordQuery{active: active, member: member, index: entry.Own})
	view := subjectView{onList: own.onList, escrowKey: own.escrowKey}
	if !r.policy.OwnOnly {
		curator := r.curator.resolve(api, recordQuery{active: api.Mul(active, sources.anyForeign), member: member, index: entry.Curator[0]})
		for i, value := range curator.onList {
			view.onList[i] = api.Select(sources.foreign[i], value, own.onList[i])
		}
	}
	return view, own.mintPolicy
}

func (r *pooledResolver) resolvePublicAsset(api frontend.API, active, asset frontend.Variable, index int) mintPolicyWires {
	return r.own.resolve(api, recordQuery{active: active, member: asset, index: r.policy.PublicAssetEntries[index]}).mintPolicy
}

func (s RecordPoolShape) validate(limits RecordPoolShape) error {
	if err := validatePoolCapacity(s.Own, s.OwnSubjects, limits.Own); err != nil {
		return err
	}
	if limits.Curator == 0 {
		if s.Curator != 0 || s.CuratorSubjects != 0 {
			return fmt.Errorf("policy own pool has curator capacity")
		}
		return nil
	}
	return validatePoolCapacity(s.Curator, s.CuratorSubjects, limits.Curator)
}

func validatePoolCapacity(records, subjects, maximum int) error {
	for _, capacity := range []int{records, subjects} {
		if capacity < 1 || capacity > maximum {
			return fmt.Errorf("policy pool capacity is invalid")
		}
	}
	return nil
}

func (e PoolEntry) validate(ownOnly bool) error {
	expected := 1
	if ownOnly {
		expected = 0
	}
	if len(e.Curator) != expected {
		return fmt.Errorf("policy curator reference shape is invalid")
	}
	return nil
}

func (p *PolicyInputs) recordCapacity(publicAssets int) RecordPoolShape {
	maximum := 1 + 2*(len(p.Outputs)+len(p.Withdrawals))
	limits := RecordPoolShape{Own: maximum + publicAssets}
	if !p.OwnOnly {
		limits.Curator = maximum
	}
	return limits
}

func (s RecordPoolShape) withDefaults(limits RecordPoolShape) RecordPoolShape {
	if s.Own == 0 {
		s.Own = limits.Own
	}
	if s.Curator == 0 {
		s.Curator = limits.Curator
	}
	if s.OwnSubjects == 0 {
		s.OwnSubjects = s.Own
	}
	if s.CuratorSubjects == 0 {
		s.CuratorSubjects = s.Curator
	}
	return s
}
