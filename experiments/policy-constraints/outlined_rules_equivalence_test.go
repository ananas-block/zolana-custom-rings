package policy_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func prototypePlan(rules []ringpolicy.Rule) policy.PrototypeRulePlan {
	var plan policy.PrototypeRulePlan
	for i, rule := range rules {
		plan[i] = policy.PrototypeRuleShape{Subject: int(rule.Subject), Guard: int(rule.Guard)}
	}
	return plan
}

func TestOutlinedPolicyBindsPlan(t *testing.T) {
	w := ringpolicy.Confidential()
	w.OwnOnly = true
	b := w.Build(t)
	c := &policy.PrototypePlannedMember{MemberPolicyCircuit: *b.Member, Plan: prototypePlan(w.Table.Rules)}
	c.Plan[0].Subject = policy.SubjectAsset
	if test.IsSolved(c, c, ecc.BN254.ScalarField()) == nil {
		t.Fatal("table with another rule subject passed")
	}
}

func TestOutlinedPolicyCounts(t *testing.T) {
	for _, shape := range []policy.MemberShape{{Outputs: 2, OwnOnly: true}, {Outputs: 2}, {Outputs: 16, Withdrawals: 32, OwnOnly: true}, {Outputs: 16, Withdrawals: 32}} {
		for _, variant := range []string{"owner_sender", "mixed"} {
			w := ringpolicy.Confidential()
			if variant == "mixed" {
				w.Table.Rules = prototypeMixedRules()
			}
			base, err := policy.NewMemberPolicyCircuitWith(shape)
			if err != nil {
				t.Fatal(err)
			}
			outlined := &policy.PrototypePlannedMember{MemberPolicyCircuit: *base, Plan: prototypePlan(w.Table.Rules)}
			counts := make([]int, 2)
			for i, circuit := range []frontend.Circuit{base, outlined} {
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				counts[i] = cs.GetNbConstraints()
			}
			if counts[1] >= counts[0] {
				t.Fatalf("%s plan did not reduce constraints %v", variant, counts)
			}
			t.Logf("outputs=%d withdrawals=%d own=%v plan=%s general=%d outlined=%d saved=%d", shape.Outputs, shape.Withdrawals, shape.OwnOnly, variant, counts[0], counts[1], counts[0]-counts[1])
		}
	}
}

func prototypeMixedRules() []ringpolicy.Rule {
	var rules []ringpolicy.Rule
	for _, subject := range []uint64{policy.SubjectOutputOwner, policy.SubjectAsset, policy.SubjectSender} {
		guards := []uint64{policy.GuardAlways}
		if subject != policy.SubjectSender {
			guards = append(guards, policy.GuardAboveAmount)
		}
		if subject == policy.SubjectOutputOwner {
			guards = append(guards, policy.GuardAboveAmountByAsset)
		}
		for _, guard := range guards {
			for _, mode := range []uint64{policy.ModePresent, policy.ModeAbsent} {
				threshold := uint64(0)
				if guard == policy.GuardAboveAmount {
					threshold = 1000
				}
				mask := uint64(1) << (2 * guard)
				if mode == policy.ModeAbsent {
					mask <<= 1
				}
				rules = append(rules, ringpolicy.Rule{Subject: subject, Mode: mode, Mask: mask, Guard: guard, Threshold: threshold})
			}
		}
	}
	for _, subject := range []uint64{policy.SubjectOutputOwner, policy.SubjectAsset} {
		rules = append(rules, ringpolicy.Rule{Subject: subject, Mode: policy.ModePresent, Mask: 5}, ringpolicy.Rule{Subject: subject, Mode: policy.ModeAbsent, Mask: 10})
	}
	return rules
}

func prototypeOutlined(b ringpolicy.Witness, plan policy.PrototypeRulePlan) frontend.Circuit {
	if b.Member != nil {
		return &policy.PrototypePlannedMember{MemberPolicyCircuit: *b.Member, Plan: plan}
	}
	return &policy.PrototypePlannedDelegate{DelegatePolicyCircuit: *b.Delegate, Plan: plan}
}

func prototypeRequireSame(t testing.TB, b ringpolicy.Witness, plan policy.PrototypeRulePlan, want bool) {
	t.Helper()
	for _, c := range []frontend.Circuit{b.Assignment(), prototypeOutlined(b, plan)} {
		err := test.IsSolved(c, c, ecc.BN254.ScalarField())
		if (err == nil) != want {
			t.Fatalf("%T acceptance=%v want=%v error=%v", c, err == nil, want, err)
		}
	}
}

func TestOutlinedPolicyExistingCases(t *testing.T) {
	for _, r := range refusals {
		t.Run(r.name, func(t *testing.T) {
			w := r.honest()
			prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), true)
			if r.world != nil {
				r.world(&w)
			}
			b := w.Build(t)
			if r.witness != nil {
				r.witness(t, b)
			}
			prototypeRequireSame(t, b, prototypePlan(w.Table.Rules), false)
		})
	}
}

func prototypePlanWorld() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Limits = nil
	w.Table.Lists = []uint64{1, 2, 4, 8, 16, 32}
	w.Table.Rules = prototypeMixedRules()
	w.Table.Inline = []ringpolicy.InlineLimit{{Asset: ringpolicy.AssetA, Limit: 1000}}
	for _, owner := range []int64{ringpolicy.Sender, ringpolicy.Alice, ringpolicy.Bob} {
		w.Own[owner] = ringpolicy.Escrowed(0x15)
	}
	w.Own[ringpolicy.AssetA] = ringpolicy.Record{Lists: 0x15}
	return w
}

func TestOutlinedPolicyEveryRuleClass(t *testing.T) {
	for _, r := range prototypeMixedRules() {
		t.Run(fmt.Sprintf("subject%d-guard%d-mode%d", r.Subject, r.Guard, r.Mode), func(t *testing.T) {
			w := prototypePlanWorld()
			w.Table.Rules = []ringpolicy.Rule{r}
			prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), true)
			identities := []int64{ringpolicy.Alice}
			if r.Subject == policy.SubjectAsset {
				identities = []int64{ringpolicy.AssetA}
			}
			if r.Subject == policy.SubjectSender {
				identities = []int64{ringpolicy.Sender}
			}
			for _, identity := range identities {
				record := w.Own[identity]
				if r.Mode == policy.ModePresent {
					record.Lists &^= r.Mask
				} else {
					record.Lists |= r.Mask
				}
				w.Own[identity] = record
			}
			if r.Guard != policy.GuardAlways {
				prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), true)
			}
			if r.Guard == policy.GuardAboveAmount {
				w.Table.Rules[0].Threshold = 1
			}
			if r.Guard == policy.GuardAboveAmountByAsset {
				w.Table.Inline[0].Limit = 1
			}
			prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), false)
		})
	}
	w := prototypePlanWorld()
	prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), true)
	w.WithdrawalCapacity = 2
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
	prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), true)
	w.Withdrawals[0].Amount = 2000
	record := w.Own[ringpolicy.Bob]
	record.Lists = 0
	w.Own[ringpolicy.Bob] = record
	prototypeRequireSame(t, w.Build(t), prototypePlan(w.Table.Rules), false)
}

func TestOutlinedPolicyCompiledSolve(t *testing.T) {
	w := prototypePlanWorld()
	w.WithdrawalCapacity = 2
	w.Withdrawals = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
	b := w.Build(t)
	outlined := prototypeOutlined(b, prototypePlan(w.Table.Rules))
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, outlined, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	outlined = prototypeOutlined(w.Build(t), prototypePlan(w.Table.Rules))
	witness, err := frontend.NewWitness(outlined, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
	w.Table.Rules[0].Subject = policy.SubjectAsset
	changed := prototypeOutlined(w.Build(t), prototypePlan(prototypeMixedRules()))
	witness, err = frontend.NewWitness(changed, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if cs.IsSolved(witness) == nil {
		t.Fatal("changed bound table subject passed")
	}
}

func prototypePooledOutlined(b ringpolicy.PooledWitness, plan policy.PrototypeRulePlan) frontend.Circuit {
	if b.Member != nil {
		return &policy.PrototypePlannedMemberV3{MemberPolicyCircuitV3: *b.Member, Plan: plan}
	}
	return &policy.PrototypePlannedDelegateV3{DelegatePolicyCircuitV3: *b.Delegate, Plan: plan}
}
func TestOutlinedPolicyPooledEquivalence(t *testing.T) {
	for _, r := range refusals {
		if r.world == nil {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			w := r.honest()
			for _, honest := range []bool{true, false} {
				if !honest {
					r.world(&w)
				}
				b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
				for _, c := range []frontend.Circuit{b.Assignment(), prototypePooledOutlined(b, prototypePlan(w.Table.Rules))} {
					if err := test.IsSolved(c, c, ecc.BN254.ScalarField()); (err == nil) != honest {
						t.Fatalf("%T acceptance=%v want=%v error=%v", c, err == nil, honest, err)
					}
				}
			}
		})
	}
}
func TestOutlinedPolicyPooledCompiledSolve(t *testing.T) {
	for _, w := range []ringpolicy.World{prototypePlanWorld(), curated(), delegate2()} {
		plan := prototypePlan(w.Table.Rules)
		schema := prototypePooledOutlined(w.Build(t).Pooled(t, policy.RecordPoolShape{}), plan)
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, schema, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
		assignment := prototypePooledOutlined(b, plan)
		witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatal(err)
		}
		b.Policy().OwnerEntries[0].Own = b.Policy().SenderEntry.Own
		witness, err = frontend.NewWitness(prototypePooledOutlined(b, plan), ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if cs.IsSolved(witness) == nil {
			t.Fatal("wrong owner subject reference passed")
		}
	}
}
func TestOutlinedPolicyPooledCounts(t *testing.T) {
	for _, shape := range []struct{ outputs, withdrawals, records int }{{2, 0, 4}, {16, 32, 50}, {16, 32, 52}, {16, 32, 68}} {
		for _, own := range []bool{true, false} {
			capacity := policy.RecordPoolShape{Own: shape.records}
			if !own {
				capacity.Curator = shape.records
			}
			makeCircuit := func() *policy.MemberPolicyCircuitV3 {
				c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: shape.outputs, Withdrawals: shape.withdrawals, OwnOnly: own}, Records: capacity})
				if err != nil {
					t.Fatal(err)
				}
				return c
			}
			base, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, makeCircuit(), frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			for _, mixed := range []bool{false, true} {
				rules := ringpolicy.Confidential().Table.Rules
				if mixed {
					rules = prototypeMixedRules()
				}
				plan := prototypePlan(rules)
				c := &policy.PrototypePlannedMemberV3{MemberPolicyCircuitV3: *makeCircuit(), Plan: plan}
				planned, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("outputs=%d withdrawals=%d records=%d own=%v mixed=%v general=%d outlined=%d saved=%d", shape.outputs, shape.withdrawals, shape.records, own, mixed, base.GetNbConstraints(), planned.GetNbConstraints(), base.GetNbConstraints()-planned.GetNbConstraints())
			}
		}
	}
}
