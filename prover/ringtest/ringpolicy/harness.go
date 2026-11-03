package ringpolicy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// SectionCircuit proves the policy section alone under rail wires, no key proves it.
type SectionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	policy.Policy
	Outputs []shared.UtxoWires
	// InputChain stays opaque, a transfer key's audit section binds the inputs.
	InputChain        frontend.Variable
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	Exempt            frontend.Variable
	KeyEscrow         frontend.Variable
	Delegate          frontend.Variable
	Published         frontend.Variable
	ApprovalRequired  frontend.Variable
	SenderPkHash      frontend.Variable
}

// SectionShape sizes a harness, Records zero takes the shape's limits.
type SectionShape struct {
	Outputs, Withdrawals int
	OwnOnly              bool
	Records              policy.RecordPoolShape
}

func NewSectionCircuit(shape SectionShape) (*SectionCircuit, error) {
	p, err := policy.NewPolicy(policy.NewPolicyInputs(shape.Outputs, shape.Withdrawals, shape.OwnOnly), shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	return &SectionCircuit{Policy: p, Outputs: make([]shared.UtxoWires, shape.Outputs)}, nil
}

func (c *SectionCircuit) Define(api frontend.API) error {
	if err := c.Validate(transaction.NPublicSlots); err != nil {
		return err
	}
	if err := shared.ValidateLength("policy", "output", len(c.Outputs), len(c.CtHashes)); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	outputs := make([]shared.Output, len(c.Outputs))
	for o, w := range c.Outputs {
		outputs[o] = w.Open(api)
	}
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{c.InputChain, gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs)), 0, c.PrivateTxBlinding}))
	approval := c.Screen(api, rc, policy.Rail{Exempt: c.Exempt, KeyEscrow: c.KeyEscrow, Delegate: c.Delegate, Published: c.Published}, c.SenderPkHash, outputs)
	api.AssertIsEqual(c.ApprovalRequired, approval)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.Statement()))
	return nil
}

// Statement binds every value the section reads from the program, in the harness's own order.
func (c *SectionCircuit) Statement() []frontend.Variable {
	fields := []frontend.Variable{c.Exempt, c.KeyEscrow, c.Delegate, c.Published, c.ApprovalRequired, c.PrivateTxHash, c.PolicyHash, c.RingProgramID, c.OwnRoot, c.CuratorRoot, c.SenderPkHash}
	fields = append(fields, c.Recipients...)
	for k := range c.PublicAssets {
		fields = append(fields, c.PublicAssets[k], c.PublicAmounts[k], c.PublicGross[k])
	}
	return append(fields, c.WithdrawalHash)
}
