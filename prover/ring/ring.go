package ring

import (
	_ "embed"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	base "github.com/helius-labs/zolana-custom-rings/prover/circuits/base"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/deposit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

const (
	// CustomRingBaseCircuitType proves the custom ring's audit statement only.
	CustomRingBaseCircuitType common.CircuitType = "custom-ring-base"

	// CustomRingPolicyCircuitType folds the audit statement with policy
	// enforcement in one proof and one verification per transact.
	CustomRingPolicyCircuitType         common.CircuitType = "custom-ring-policy"
	CustomRingDelegatePolicyCircuitType common.CircuitType = "custom-ring-delegate-policy"

	// Windowed members must seal their successor counters for disclosure.
	CustomRingCompressedPolicyCircuitType common.CircuitType = "custom-ring-compressed-policy"

	// Key registration inserts a member's auditor-encrypted nullifier key at the cursor.
	CustomRingKeyRegisterCircuitType common.CircuitType = "custom-ring-register-key"

	// Deposit openings must be encrypted for the configured auditor.
	CustomRingDepositCircuitType common.CircuitType = "custom-ring-deposit"
)

const CustomRingPolicyKeyFile = "custom_ring_policy.key"
const CustomRingDelegatePolicyKeyFile = "custom_ring_delegate_policy.key"

const CustomRingBaseKeyFile = "custom_ring_base.key"

const CustomRingCompressedPolicyKeyFile = "custom_ring_compressed_policy.key"

const CustomRingKeyRegisterKeyFile = "custom_ring_register_key.key"
const CustomRingDepositKeyFile = "custom_ring_deposit.key"

// Pins every ring key, all of them release assets.
//
//go:embed proving-keys.lock
var lockfile []byte

var (
	policyRing = common.ExtensionCircuit{
		Type:    CustomRingPolicyCircuitType,
		KeyFile: CustomRingPolicyKeyFile,
		Circuit: func() frontend.Circuit { return &policy.CustomRingPolicyCircuit{} },
		Request: func() common.ExtensionRequest { return new(PolicyParameters) },
	}
	baseRing = common.ExtensionCircuit{
		Type:    CustomRingBaseCircuitType,
		KeyFile: CustomRingBaseKeyFile,
		Circuit: func() frontend.Circuit { return &base.CustomRingBaseCircuit{} },
		Request: func() common.ExtensionRequest { return new(BaseParameters) },
	}
	delegatePolicyRing = common.ExtensionCircuit{
		Type:    CustomRingDelegatePolicyCircuitType,
		KeyFile: CustomRingDelegatePolicyKeyFile,
		Circuit: func() frontend.Circuit { return &policy.CustomRingDelegatePolicyCircuit{} },
		Request: func() common.ExtensionRequest { return new(DelegatePolicyParameters) },
	}
	compressedPolicyRing = common.ExtensionCircuit{
		Type:    CustomRingCompressedPolicyCircuitType,
		KeyFile: CustomRingCompressedPolicyKeyFile,
		Circuit: func() frontend.Circuit { return &policy.CompressedPolicyCircuit{} },
		Request: func() common.ExtensionRequest { return new(CompressedPolicyParameters) },
	}
	keyRegisterRing = common.ExtensionCircuit{
		Type:    CustomRingKeyRegisterCircuitType,
		KeyFile: CustomRingKeyRegisterKeyFile,
		Circuit: func() frontend.Circuit { return &policy.KeyRegisterCircuit{} },
		Request: func() common.ExtensionRequest { return new(KeyRegisterParameters) },
	}
	depositRing = common.ExtensionCircuit{
		Type:    CustomRingDepositCircuitType,
		KeyFile: CustomRingDepositKeyFile,
		Circuit: func() frontend.Circuit { return &deposit.CustomRingDepositCircuit{} },
		Request: func() common.ExtensionRequest { return new(DepositParameters) },
	}
)

var RingCircuits = []common.ExtensionCircuit{
	policyRing,
	baseRing,
	delegatePolicyRing,
	compressedPolicyRing,
	keyRegisterRing,
	depositRing,
}

func init() {
	for _, circuit := range RingCircuits {
		common.RegisterExtension(circuit)
	}
	provingkeys.Register(lockfile)
}

func R1CSPolicy() (constraint.ConstraintSystem, error) {
	return policyRing.R1CS()
}

func R1CSBase() (constraint.ConstraintSystem, error) {
	return baseRing.R1CS()
}

func R1CSDelegatePolicy() (constraint.ConstraintSystem, error) {
	return delegatePolicyRing.R1CS()
}

func R1CSCompressedPolicy() (constraint.ConstraintSystem, error) {
	return compressedPolicyRing.R1CS()
}

func R1CSKeyRegister() (constraint.ConstraintSystem, error) {
	return keyRegisterRing.R1CS()
}

func R1CSDeposit() (constraint.ConstraintSystem, error) {
	return depositRing.R1CS()
}

func (p *PolicyParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *BaseParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *DelegatePolicyParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *CompressedPolicyParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *KeyRegisterParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}

func (p *DepositParameters) Assignment() (frontend.Circuit, error) {
	return p.CreateWitness()
}
