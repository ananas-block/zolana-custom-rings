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
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
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
	{Inputs: 32, Outputs: 2, Withdrawals: 4},
	{Inputs: 32, Outputs: 2, Withdrawals: 32},
	{Inputs: 24, Outputs: 4, Withdrawals: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 32},
	{Inputs: 16, Outputs: 8, Withdrawals: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 32},
	{Inputs: 5, Outputs: 16, Withdrawals: 8},
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
	Outputs           []audit.DeliveryWires
	// InputCount is the published nullifier count, the in-proof and authority evidence opens the slots below it.
	InputCount frontend.Variable
	// Inputs open on the in-proof and authority rails, every slot a dummy on the signer rail.
	Inputs []shared.UtxoWires
	// InputChain is the chain SPP proves over the inputs while they stay closed.
	InputChain frontend.Variable
	transactionBinding
	// Sender is the statement's sender identity, zero on the authority rail.
	Sender frontend.Variable
	// SenderPkHash is the member an authority move spends.
	SenderPkHash frontend.Variable
	screenedPolicy
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
		Shape:          shape,
		Outputs:        make([]audit.DeliveryWires, shape.Outputs),
		Inputs:         make([]shared.UtxoWires, shape.Inputs),
		screenedPolicy: screenedPolicy{Policy: p},
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
	// 1. The rail bits are bits, the authority rail names no public sender and no in-proof owner.
	c.assertRail(api)
	// 2. The transaction key opens and its seed fixes every output blinding.
	envelope := w.OpenEnvelope(api, rc)
	// 3. The layout names the one key, the authority rail escrows keys.
	keyEscrow := c.decodeLayout(api)
	// 4. Every slot opens once, the sections below read the same wires.
	opened := audit.OpenSlots(api, rc, w, envelope, c.Outputs)
	// 5. The in-proof and authority rails open every input to the sender, the signer rail keeps SPP's input chain.
	spend := c.spendInputs(api, rc)
	// 6. SPP's private transaction hash reopens over the opened slots with no address input.
	c.bindTransaction(api, spend.inputChain, opened.Slots)
	// 7. The auditor stream seals tx_viewing_sk, the input evidence and every exit's record.
	stream := w.SealStream(api, audit.ConfidentialRanges(c.Shape.Inputs, c.Shape.Outputs), spend.evidence, opened.ExitRecords())
	// 8. Every ring output's body opens for its recipient and the auditor.
	delivered := w.Deliver(api, envelope, keyEscrow, c.Outputs, opened, stream)
	// 9. The policy screens the same slots under the rail, every recipient published, the authority rail bounds no outflow.
	c.screen(api, rc, policy.Rail{KeyEscrow: keyEscrow, Delegate: c.Delegate, Published: 1}, spend.sender, opened.Slots)
	// 10. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, stream, opened, delivered)))
	return nil
}

func (c *ConfidentialTransferCircuit) assertRail(api frontend.API) {
	for _, bit := range []frontend.Variable{c.InProof, c.Delegate, c.ApprovalRequired} {
		api.AssertIsBoolean(bit)
	}
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.InProof})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.Sender})
}

// decodeLayout pins bit 0 and full openings clear and returns key escrow, set on the authority rail.
func (c *ConfidentialTransferCircuit) decodeLayout(api frontend.API) frontend.Variable {
	keyEscrow := audit.DecodeLayout(api, c.Layout, audit.LayoutEscrow, 0).Flag(audit.LayoutEscrow)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: api.Sub(1, keyEscrow)})
	return keyEscrow
}

type confidentialSpend struct {
	sender, inputChain frontend.Variable
	evidence           audit.Evidence
}

// spendInputs selects the evidence by the rail bits, a mismatch would let the signer rail open a note or an owner rail hide one.
func (c *ConfidentialTransferCircuit) spendInputs(api frontend.API, rc frontend.Rangechecker) confidentialSpend {
	// 1. The authority rail screens its private member, the other rails the statement's sender.
	sender := api.Select(c.Delegate, c.SenderPkHash, c.Sender)
	// 2. On the signer rail the selection reads zero at any input_count, no entry is transmitted and every slot stays a dummy, on the other rails SelectCount refuses a count past the class.
	inputsOpen := api.Or(c.InProof, c.Delegate)
	count := ringgadget.SelectCount(api, api.Mul(inputsOpen, c.InputCount), 0, c.Shape.Inputs+1)
	// 3. While inputs open input 0 is a UTXO and every UTXO lies below the count and is the sender's.
	hashes := audit.SpentBySender(api, c.Inputs, count.Active, inputsOpen, sender)
	return confidentialSpend{
		sender: sender,
		// 4. SPP's private transaction hash reads the opened hashes while inputs open and the chain SPP proves on the signer rail.
		inputChain: api.Select(inputsOpen, gadget.NonZeroHashChain(api, hashes), c.InputChain),
		evidence:   audit.InputPrefixEvidence(api, rc, hashes, count),
	}
}

// statement is the confidential transfer preimage, mirrored by TransferStatement::elements under TransferFamily::Confidential in program-libs/interface/src/proof/statement.rs.
//
//	head ‖ in_proof, delegate, exempt, approval_required, output_chain, output_ciphertext_chain, recipient_key_chain,
//	input_count, exits_bitmap, private_tx_hash, sender, policy_hash, own_root, curator_root,
//	recipient per output, asset, net and gross per public slot, withdrawal_hash, length, version
func (c *ConfidentialTransferCircuit) statement(e audit.Envelope, w audit.AuditWires, stream audit.Stream, opened audit.Opened, d audit.Delivered) []frontend.Variable {
	fields := slices.Concat(e.Head(w, stream, shared.TransferStatementDomain), []frontend.Variable{
		c.InProof, c.Delegate, c.Exempt, c.ApprovalRequired,
		opened.OutputChain, d.OutputCiphertextChain, d.RecipientKeyChain,
		c.InputCount, opened.ExitsBitmap, c.PrivateTxHash, c.Sender, c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, c.Recipients, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash))
}
