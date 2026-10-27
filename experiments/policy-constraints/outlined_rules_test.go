package policy

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type PrototypeRuleShape struct{ Subject, Guard int }
type PrototypeRulePlan [NRules]PrototypeRuleShape
type PrototypePlannedMember struct {
	MemberPolicyCircuit
	Plan PrototypeRulePlan `gnark:"-"`
}
type PrototypePlannedDelegate struct {
	DelegatePolicyCircuit
	Plan PrototypeRulePlan `gnark:"-"`
}
type PrototypePlannedMemberV3 struct {
	MemberPolicyCircuitV3
	Plan PrototypeRulePlan `gnark:"-"`
}
type PrototypePlannedDelegateV3 struct {
	DelegatePolicyCircuitV3
	Plan PrototypeRulePlan `gnark:"-"`
}

func (c *PrototypePlannedMember) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	return prototypeMemberDefine(api, &c.MemberPolicyCircuit, &c.Policy, c.Plan, 2)
}
func (c *PrototypePlannedDelegate) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	return prototypeDelegateDefine(api, &c.DelegatePolicyCircuit, &c.Policy, c.Plan, 2)
}
func (c *PrototypePlannedMemberV3) Define(api frontend.API) error {
	if err := c.PolicyV3.validate(transaction.NPublicSlots); err != nil {
		return err
	}
	legacy := MemberPolicyCircuit{MemberPolicyValues: c.MemberPolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return prototypeMemberDefine(api, &legacy, &pooledResolver{policy: &c.PolicyV3}, c.Plan, 3)
}
func (c *PrototypePlannedDelegateV3) Define(api frontend.API) error {
	if len(c.Inputs) == 0 {
		return fmt.Errorf("policy requires a delegate input")
	}
	if err := c.PolicyV3.validate(0); err != nil {
		return err
	}
	legacy := DelegatePolicyCircuit{DelegatePolicyValues: c.DelegatePolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return prototypeDelegateDefine(api, &legacy, &pooledResolver{policy: &c.PolicyV3}, c.Plan, 3)
}
func prototypeMemberDefine(api frontend.API, c *MemberPolicyCircuit, resolver subjectResolver, plan PrototypeRulePlan, version int) error {
	rc := rangecheck.New(api)
	cmp := c.comparator(rc)
	t := c.Table.decode(api, rc, c.PolicyHash)
	c.assertOwnOnly(api)
	outputs := c.openOutputs(api, c.InputChain)
	sender := c.sender(api)
	s, err := plan.resolveAndAssert(api, rc, &c.PolicyInputs, resolver, t, sender, outputs, version)
	if err != nil {
		return err
	}
	c.assertApproval(api, c.constrainOutflow(api, cmp, sender, outputs, s.mintPolicies[:len(outputs)], resolver))
	c.assertEscrow(api, c.KeyEscrow, s.owners, outputs)
	bindStatement(api, c.PublicInputHash, c.statementVersion(c.rail(), version))
	return nil
}
func prototypeDelegateDefine(api frontend.API, c *DelegatePolicyCircuit, resolver subjectResolver, plan PrototypeRulePlan, version int) error {
	rc := rangecheck.New(api)
	t := c.Table.decode(api, rc, c.PolicyHash)
	c.assertOwnOnly(api)
	inputs, inputChain := openInputs(api, c.Inputs)
	outputs := c.openOutputs(api, inputChain)
	sender := c.sender(api, inputs)
	s, err := plan.resolveAndAssert(api, rc, &c.PolicyInputs, resolver, t, sender, outputs, version)
	if err != nil {
		return err
	}
	c.assertEscrow(api, delegateRail.keyEscrow, s.owners, outputs)
	bindStatement(api, c.PublicInputHash, c.statementVersion(delegateRail, version))
	return nil
}
func (plan PrototypeRulePlan) resolveAndAssert(api frontend.API, rc frontend.Rangechecker, p *PolicyInputs, resolver subjectResolver, t tableView, sender frontend.Variable, outputs []utxoView, version int) (subjects, error) {
	payments := append(append([]utxoView{}, outputs...), p.openWithdrawals(api, rc, version)...)
	s, err := resolver.resolveSubjects(api, t, sender, payments)
	if err != nil {
		return subjects{}, err
	}
	if err := plan.assertRules(api, p.comparator(rc), t, s, payments); err != nil {
		return subjects{}, err
	}
	return s, nil
}
func (plan PrototypeRulePlan) bind(api frontend.API, t tableView) (bool, bool, bool, error) {
	needTotals, needAssetGuard, scalarOwner := false, false, false
	for r, shape := range plan {
		active := shape.Subject != 0
		api.AssertIsEqual(t.ruleActive[r], prototypeBit(active))
		if !active {
			continue
		}
		if err := shape.check(); err != nil {
			return false, false, false, err
		}
		rule := t.rules[r]
		api.AssertIsEqual(rule.onOwner, prototypeBit(shape.Subject == SubjectOutputOwner))
		api.AssertIsEqual(rule.onAsset, prototypeBit(shape.Subject == SubjectAsset))
		api.AssertIsEqual(rule.onSender, prototypeBit(shape.Subject == SubjectSender))
		api.AssertIsEqual(rule.scalarGuard, prototypeBit(shape.Guard == GuardAboveAmount))
		api.AssertIsEqual(rule.assetGuard, prototypeBit(shape.Guard == GuardAboveAmountByAsset))
		needTotals = needTotals || shape.Guard != GuardAlways
		needAssetGuard = needAssetGuard || shape.Guard == GuardAboveAmountByAsset
		scalarOwner = scalarOwner || shape.Subject == SubjectOutputOwner && shape.Guard == GuardAboveAmount
	}
	return needTotals, needAssetGuard, scalarOwner, nil
}

func (plan PrototypeRulePlan) assertRules(api frontend.API, cmp comparator, t tableView, s subjects, outputs []utxoView) error {
	needTotals, needAssetGuard, scalarOwner, err := plan.bind(api, t)
	if err != nil {
		return err
	}
	liveOwner := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		liveOwner[o] = api.Mul(out.utxo, ringgadget.IsNonZero(api, out.ownerPkHash))
	}
	var totals []outputTotals
	if needTotals {
		totals = sumOutputs(api, outputs, liveOwner)
	}
	assetExempt := make([]frontend.Variable, len(outputs))
	if needAssetGuard {
		for o := range outputs {
			assetExempt[o] = cmp.atMost(api, totals[o].byOwnerAndAsset, s.mintPolicies[o].threshold)
		}
	}
	if scalarOwner {
		asset, seen := outputs[0].asset, outputs[0].utxo
		for _, out := range outputs[1:] {
			api.AssertIsEqual(api.Mul(seen, out.utxo, api.Sub(asset, out.asset)), 0)
			asset = api.Select(out.utxo, out.asset, asset)
			seen = api.Or(seen, out.utxo)
		}
	}
	for r, shape := range plan {
		shape.assertRule(api, cmp, t.rules[r], s, outputs, liveOwner, totals, assetExempt)
	}
	return nil
}

func (shape PrototypeRuleShape) check() error {
	switch shape.Subject {
	case SubjectOutputOwner, SubjectAsset, SubjectSender:
	default:
		return fmt.Errorf("invalid plan subject %d", shape.Subject)
	}
	switch shape.Guard {
	case GuardAlways:
	case GuardAboveAmount:
		if shape.Subject == SubjectSender {
			return fmt.Errorf("invalid plan guard %d", shape.Guard)
		}
	case GuardAboveAmountByAsset:
		if shape.Subject != SubjectOutputOwner {
			return fmt.Errorf("invalid plan guard %d", shape.Guard)
		}
	default:
		return fmt.Errorf("invalid plan guard %d", shape.Guard)
	}
	return nil
}

func (shape PrototypeRuleShape) assertRule(api frontend.API, cmp comparator, rule ruleFields, s subjects, outputs []utxoView, liveOwner []frontend.Variable, totals []outputTotals, assetExempt []frontend.Variable) {
	if shape.Subject == 0 {
		return
	}
	if shape.Subject == SubjectSender {
		api.AssertIsEqual(rule.refuses(api, s.sender.onList), 0)
		return
	}
	for o, out := range outputs {
		active, lists := liveOwner[o], s.owners[o].onList
		if shape.Subject == SubjectAsset {
			active, lists = out.utxo, s.assets[o].onList
		}
		exempt := frontend.Variable(0)
		switch shape.Guard {
		case GuardAboveAmount:
			total := totals[o].byOwner
			if shape.Subject == SubjectAsset {
				total = totals[o].byAsset
			}
			exempt = cmp.atMost(api, total, rule.threshold)
		case GuardAboveAmountByAsset:
			transaction.AssertWhen(api, active, ringgadget.IsNonZero(api, s.mintPolicies[o].threshold))
			exempt = assetExempt[o]
		}
		transaction.AssertWhen(api, api.Mul(active, rule.refuses(api, lists)), exempt)
	}
}

func prototypeBit(value bool) int {
	if value {
		return 1
	}
	return 0
}
