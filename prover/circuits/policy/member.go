package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

var MemberOutputs = [...]int{2, 4, 8, 16}

type MemberPolicyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	// Anonymous selects how Sender reads, the owner signer identity or the sender commitment.
	Anonymous        frontend.Variable
	ApprovalRequired frontend.Variable
	KeyEscrow        frontend.Variable
	Sender           frontend.Variable
	// InputChain stays opaque, the program's sole owner signer or the anonymous audit proof binds every input to the sender.
	InputChain frontend.Variable
	Policy
}

type MemberShape struct {
	Outputs, Withdrawals int
	OwnOnly              bool
}

var WithdrawalCapacities = []int{0, 1, 2, 4, 8, 16, 32}

func NewMemberPolicyCircuit(outputs int) (*MemberPolicyCircuit, error) {
	return NewMemberPolicyCircuitWith(MemberShape{Outputs: outputs})
}

func NewMemberPolicyCircuitWith(shape MemberShape) (*MemberPolicyCircuit, error) {
	outputs := shape.Outputs
	if !slices.Contains(WithdrawalCapacities, shape.Withdrawals) {
		return nil, fmt.Errorf("policy: unsupported withdrawal capacity %d", shape.Withdrawals)
	}

	if !slices.Contains(MemberOutputs[:], outputs) {
		return nil, fmt.Errorf("policy: no member key for %d outputs", outputs)
	}
	return &MemberPolicyCircuit{Policy: newPolicy(outputs, shape.Withdrawals, shape.OwnOnly)}, nil
}

func (c *MemberPolicyCircuit) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	cmp := c.comparator(rc)
	// 1. The rules read the table under policy_hash.
	t := c.Table.decode(api, rc, c.PolicyHash)
	c.assertOwnOnly(api)
	// 2. The outputs open private_tx_hash beside the input chain SPP proves.
	outputs := c.openOutputs(api, c.InputChain)
	// 3. One sender, the owner signer, or on an anonymous ring the sender its commitment hides.
	sender := c.sender(api)
	// 4. The sender and every UTXO output's subjects open under own_root, and under curator_root when a list is foreign.
	payments := append(append([]utxoView{}, outputs...), c.openWithdrawals(api, rc)...)
	s := c.resolveSubjects(api, t, sender, payments)
	// 5. Every enabled rule holds for its subjects.
	c.assertRules(api, cmp, t, s, payments)
	// 6. Every limit row bounds the outflow, approval_required says whether one passes its co-sign bound.
	c.assertApproval(api, c.constrainOutflow(api, cmp, t, sender, outputs))
	// 7. Under key escrow every output owner escrows the output's nullifier key.
	c.assertEscrow(api, c.KeyEscrow, s.owners, outputs)
	// 8. The one public input is the statement the program rebuilds.
	bindStatement(api, c.PublicInputHash, c.Statement())
	return nil
}

func (c *MemberPolicyCircuit) sender(api frontend.API) frontend.Variable {
	// 1. The anonymous audit proof opens the same commitment to the sender owning every input.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: c.Anonymous, A: c.Sender, B: shared.SenderCommitment(api, c.SenderPkHash, c.PrivateTxBlinding)})
	// 2. The select also holds the anonymous bit to 0 or 1, a fraction would blend the two senders.
	return api.Select(c.Anonymous, c.SenderPkHash, c.Sender)
}

func (c *MemberPolicyCircuit) assertApproval(api frontend.API, approval frontend.Variable) {
	// A transfer past a co-sign bound demands the co-signer, one within every bound claims no approval.
	api.AssertIsEqual(c.ApprovalRequired, approval)
}

func (c *MemberPolicyCircuit) rail() railValues {
	return railValues{
		anonymous:        []frontend.Variable{c.Anonymous},
		approvalRequired: c.ApprovalRequired,
		keyEscrow:        c.KeyEscrow,
		sender:           c.Sender,
	}
}

func (c *MemberPolicyCircuit) Statement() []frontend.Variable { return c.statement(c.rail()) }
