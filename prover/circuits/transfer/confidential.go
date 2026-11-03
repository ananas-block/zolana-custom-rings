package transfer

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// ConfidentialShape sizes a key, Inputs the slots the in-proof and authority rails open.
type ConfidentialShape struct {
	Inputs, Outputs, Withdrawals int
	Records                      policy.RecordPoolShape
}

// ConfidentialShapes are the confidential keys, mirrored by CONFIDENTIAL_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var ConfidentialShapes = [...]ConfidentialShape{
	{Inputs: 40, Outputs: 2, Withdrawals: 4},
	{Inputs: 40, Outputs: 2, Withdrawals: 32},
	{Inputs: 24, Outputs: 4, Withdrawals: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 32},
	{Inputs: 16, Outputs: 8, Withdrawals: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 32},
	{Inputs: 8, Outputs: 16, Withdrawals: 8},
}

func (s ConfidentialShape) String() string {
	return fmt.Sprintf("custom_ring_transfer_confidential_%d_in%d_w%d", s.Outputs, s.Inputs, s.Withdrawals)
}

type ConfidentialTransferCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Shape           ConfidentialShape `gnark:"-"`
	auditStatementWires
	// InProof and Delegate name the rail, the signer rail carries neither.
	InProof, Delegate frontend.Variable
	Exempt            frontend.Variable
	ApprovalRequired  frontend.Variable
	Outputs           []audit.DeliveryWires
	// Inputs open on the in-proof and authority rails, every slot a dummy on the signer rail.
	Inputs []shared.UtxoWires
	// InputChain is the chain SPP proves over the inputs while they stay closed.
	InputChain frontend.Variable
	transactionBinding
	// Sender is the statement's sender identity, zero on the authority rail.
	Sender frontend.Variable
	// SenderPkHash is the member an authority move spends.
	SenderPkHash frontend.Variable
	policy.Policy
}

func NewConfidentialTransferCircuit(shape ConfidentialShape) (*ConfidentialTransferCircuit, error) {
	keyed := ConfidentialShape{Inputs: shape.Inputs, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals}
	if !slices.Contains(ConfidentialShapes[:], keyed) {
		return nil, fmt.Errorf("transfer: unsupported confidential shape %+v, want one of %v", keyed, ConfidentialShapes)
	}
	p, err := policy.NewPolicy(policy.NewPolicyInputs(shape.Outputs, shape.Withdrawals, false), shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	return &ConfidentialTransferCircuit{
		Shape:   shape,
		Outputs: make([]audit.DeliveryWires, shape.Outputs),
		Inputs:  make([]shared.UtxoWires, shape.Inputs),
		Policy:  p,
	}, nil
}

func (c *ConfidentialTransferCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), c.Shape.Inputs),
		shared.ValidateLength("transfer", "escrow hash", len(c.CtHashes), c.Shape.Outputs),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), c.Shape.Withdrawals),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	w := c.auditWires(c.RingProgramID)
	for _, bit := range []frontend.Variable{c.InProof, c.Delegate, c.Exempt, c.ApprovalRequired} {
		api.AssertIsBoolean(bit)
	}
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.InProof})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.Sender})
	envelope := w.Seal(api, rc)
	layout := audit.DecodeLayout(api, c.Layout, audit.LayoutExits|audit.LayoutEscrow|audit.LayoutReserved, 0)
	keyEscrow := layout.Flag(audit.LayoutEscrow)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: api.Sub(1, keyEscrow)})
	// Live ring bodies bind their openings, exit recipient bodies remain outside the proof.
	delivered := w.Deliver(api, rc, envelope, layout, c.Outputs)
	opened := api.Or(c.InProof, c.Delegate)
	sender := api.Select(c.Delegate, c.SenderPkHash, c.Sender)
	inputHashes := audit.SpentBySender(api, c.Inputs, opened, opened, sender)
	inputChain := api.Select(opened, gadget.NonZeroHashChain(api, inputHashes), c.InputChain)
	c.bindTransaction(api, inputChain, delivered.Slots)
	approval := c.Screen(api, rc, policy.Rail{Exempt: c.Exempt, KeyEscrow: keyEscrow, Delegate: c.Delegate, Published: 1}, sender, delivered.Slots)
	api.AssertIsEqual(c.ApprovalRequired, approval)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, delivered, delivered.Disclosure(api, envelope, layout))))
	return nil
}

// statement is the confidential transfer preimage, mirrored by TransferStatement::elements under TransferFamily::Confidential in program-libs/interface/src/proof/statement.rs.
//
//	head ‖ in_proof, delegate, exempt, approval_required, output_chain, body_chain, recipient_key_chain, disclosure_chain,
//	private_tx_hash, sender, policy_hash, own_root, curator_root, recipient per output, asset, net and gross per public slot, withdrawal_hash, length, version
func (c *ConfidentialTransferCircuit) statement(e audit.Envelope, w audit.AuditWires, d audit.Delivered, disclosure frontend.Variable) []frontend.Variable {
	fields := slices.Concat(e.Head(w, shared.TransferStatementDomain), []frontend.Variable{
		c.InProof, c.Delegate, c.Exempt, c.ApprovalRequired,
		d.OutputChain, d.BodyChain, d.RecipientKeyChain, disclosure,
		c.PrivateTxHash, c.Sender, c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, c.Recipients, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash))
}
