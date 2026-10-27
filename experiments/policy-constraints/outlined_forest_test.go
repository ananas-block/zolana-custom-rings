package policy

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"testing"
)

type outlinedForestCircuit struct {
	forestCircuit
	Plan PrototypeRulePlan `gnark:"-"`
}

func (c *outlinedForestCircuit) Define(api frontend.API) error {
	legacy := MemberPolicyCircuit{MemberPolicyValues: c.MemberPolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return prototypeMemberDefine(api, &legacy, &forestResolver{policy: &c.PolicyInputs, witness: &c.Forest}, c.Plan, 3)
}
func TestOutlinedForestCounts(t *testing.T) {
	for _, shape := range []MemberShape{{Outputs: 2, OwnOnly: true}, {Outputs: 16, Withdrawals: 32}} {
		for _, assetHeight := range []int{1, 5} {
			general, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newForest(shape, 3, 10, assetHeight), frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			for _, mixed := range []bool{false, true} {
				plan := PrototypeRulePlan{{Subject: SubjectOutputOwner}, {Subject: SubjectSender}}
				if mixed {
					plan = PrototypeRulePlan{}
					index := 0
					for _, subject := range []int{SubjectOutputOwner, SubjectAsset, SubjectSender} {
						guards := []int{GuardAlways}
						if subject != SubjectSender {
							guards = append(guards, GuardAboveAmount)
						}
						if subject == SubjectOutputOwner {
							guards = append(guards, GuardAboveAmountByAsset)
						}
						for _, guard := range guards {
							for repeat := 0; repeat < 2; repeat++ {
								plan[index] = PrototypeRuleShape{Subject: subject, Guard: guard}
								index++
							}
						}
					}
					for _, subject := range []int{SubjectOutputOwner, SubjectAsset} {
						for repeat := 0; repeat < 2; repeat++ {
							plan[index] = PrototypeRuleShape{Subject: subject}
							index++
						}
					}
				}
				c := &outlinedForestCircuit{forestCircuit: *newForest(shape, 3, 10, assetHeight), Plan: plan}
				cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("outputs=%d withdrawals=%d assets=3 participantHeight=10 assetHeight=%d own=%v mixed=%v forest=%d outlined=%d saved=%d", shape.Outputs, shape.Withdrawals, assetHeight, shape.OwnOnly, mixed, general.GetNbConstraints(), cs.GetNbConstraints(), general.GetNbConstraints()-cs.GetNbConstraints())
			}
		}
	}
}
