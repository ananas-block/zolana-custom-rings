package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type DelegatePolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Inputs          []shared.UtxoWires
	Policy
}

var delegateRail = railValues{approvalRequired: 0, keyEscrow: 1, sender: 0}

func NewDelegatePolicyCircuit(shape transaction.Shape) (*DelegatePolicyCircuit, error) {
	if err := shape.Validate(); err != nil {
		return nil, fmt.Errorf("policy: no delegate key, %w", err)
	}
	return &DelegatePolicyCircuit{Inputs: make([]shared.UtxoWires, shape.NInputs), Policy: newPolicy(shape.NOutputs)}, nil
}

func (c *DelegatePolicyCircuit) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	cmp := c.comparator(rc)
	// 1. The rules read the table under policy_hash.
	t := c.Table.decode(api, rc, c.PolicyHash)
	// 2. The reopened inputs and the outputs open private_tx_hash.
	inputs, inputChain := openInputs(api, c.Inputs)
	outputs := c.openOutputs(api, inputChain)
	// 3. A delegate move spends one member, the sender.
	sender := c.sender(api, inputs)
	// 4. The sender and every output's owner and asset are opened under own_root, and under curator_root when a list is foreign.
	s := c.resolveSubjects(api, t, sender, outputs)
	// 5. Every enabled rule holds for its subjects.
	c.assertRules(api, cmp, t, s, outputs)
	// 6. The key fixes approval_required to 0, the program authorizes the configured delegate signer instead.
	// 7. The key fixes key_escrow to 1, every output owner escrows the output's nullifier key.
	c.assertEscrow(api, delegateRail.keyEscrow, s.owners, outputs)
	// 8. The one public input is the statement the program rebuilds, its sender value is 0.
	bindStatement(api, c.PublicInputHash, c.Statement())
	return nil
}

func (c *DelegatePolicyCircuit) validate() error {
	if len(c.Inputs) == 0 {
		return fmt.Errorf("policy: a delegate move reopens at least one input")
	}
	return c.Policy.validate()
}

func (c *DelegatePolicyCircuit) sender(api frontend.API, inputs []utxoView) frontend.Variable {
	// 1. Input 0 is a UTXO, the sender owns at least one spent input.
	api.AssertIsEqual(inputs[0].utxo, 1)
	for _, in := range inputs {
		// 2. Every UTXO input belongs to the sender.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: in.utxo, A: in.ownerPkHash, B: c.SenderPkHash})
	}
	return c.SenderPkHash
}

func (c *DelegatePolicyCircuit) Statement() []frontend.Variable { return c.statement(delegateRail) }
