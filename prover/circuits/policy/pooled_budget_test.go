package policy_test

import (
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

func TestPooledPolicyGeneralBudget(t *testing.T) {
	c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 16, Withdrawals: 32, OwnOnly: true}})
	if err != nil {
		t.Fatal(err)
	}
	if count := ringkey.Compile(t, c).GetNbConstraints(); count >= 390000 {
		t.Fatalf("general policy has %d constraints", count)
	}
}
