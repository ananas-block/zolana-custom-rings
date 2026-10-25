package policy_test

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"math/big"
	"testing"
)

func TestWithdrawalExemptionAuthenticatesUnboundedMintRecords(t *testing.T) {
	solve := func(c *policy.WithdrawalExemptionCircuit) error {
		return test.IsSolved(&policy.WithdrawalExemptionCircuit{}, c, ecc.BN254.ScalarField())
	}
	if err := solve(ringpolicy.Exemption(t)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*policy.WithdrawalExemptionCircuit){
		"above threshold":          func(c *policy.WithdrawalExemptionCircuit) { c.Amounts[0] = 101 },
		"forged threshold":         func(c *policy.WithdrawalExemptionCircuit) { c.Amounts[0] = 101; c.Entries[0].WithdrawalThreshold = 101 },
		"another mint":             func(c *policy.WithdrawalExemptionCircuit) { c.Assets[0] = 11 },
		"another root":             func(c *policy.WithdrawalExemptionCircuit) { c.Root = 1 },
		"padding hides withdrawal": func(c *policy.WithdrawalExemptionCircuit) { c.Amounts[2] = 1 },
		"overflow":                 func(c *policy.WithdrawalExemptionCircuit) { c.Amounts[0] = new(big.Int).Lsh(big.NewInt(1), 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := ringpolicy.Exemption(t)
			mutate(c)
			ringpolicy.BindExemption(t, c)
			if solve(c) == nil {
				t.Fatal("invalid exemption solved")
			}
		})
	}
}
