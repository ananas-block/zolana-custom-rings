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

// ConfidentialShape sizes a key, Inputs the slots every rail opens and the signers it can bind.
type ConfidentialShape struct {
	Inputs, Outputs, Withdrawals int
}

// ConfidentialShapes are the confidential keys, mirrored by CONFIDENTIAL_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var ConfidentialShapes = [...]ConfidentialShape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4},
	{Inputs: 24, Outputs: 2, Withdrawals: 32},
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
	OutputCount       frontend.Variable
	Outputs           []audit.DeliveryWires
	InputCount        frontend.Variable
	Inputs            []shared.UtxoWires
	transactionBinding
	// Sender is the in-proof owner, zero on the signer and authority rails.
	Sender frontend.Variable
	// SenderPkHash is the member an authority move spends.
	SenderPkHash frontend.Variable
	SignerCount  frontend.Variable
	// Signers is the program's owner signer run, zero past SignerCount.
	Signers []frontend.Variable
	screenedPolicy
}

func NewConfidentialTransferCircuit(shape ConfidentialShape) (*ConfidentialTransferCircuit, error) {
	keyed := ConfidentialShape{Inputs: shape.Inputs, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals}
	if !slices.Contains(ConfidentialShapes[:], keyed) {
		return nil, fmt.Errorf("transfer: unsupported confidential shape %+v, want one of %v", keyed, ConfidentialShapes)
	}
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: screenedOwners}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	return &ConfidentialTransferCircuit{
		Shape:          shape,
		Outputs:        make([]audit.DeliveryWires, shape.Outputs),
		Inputs:         make([]shared.UtxoWires, shape.Inputs),
		Signers:        make([]frontend.Variable, shape.Inputs),
		screenedPolicy: screenedPolicy{Policy: p},
	}, nil
}

func (c *ConfidentialTransferCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), c.Shape.Inputs),
		shared.ValidateLength("transfer", "signer", len(c.Signers), c.Shape.Inputs),
		shared.ValidateLength("transfer", "escrow hash", len(c.CtHashes), c.Shape.Outputs),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), c.Shape.Withdrawals),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	w := c.auditWires(c.RingProgramID)
	// The rail bits are bits, only the in-proof rail names a public sender.
	c.assertRail(api)
	envelope := w.OpenEnvelope(api, rc)
	keyEscrow := c.decodeLayout(api)
	opened := audit.OpenSlots(api, rc, w, envelope, c.Outputs, c.OutputCount)
	g := c.gates(api, policy.Rail{KeyEscrow: keyEscrow, Delegate: c.Delegate, Published: 1, Delivery: 0})
	spend := c.spendInputs(api, g.Screened)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, spend.section.Hashes), opened.Slots)
	stream := w.SealStream(api, audit.ConfidentialRanges(c.Shape.Inputs, c.Shape.Outputs), audit.InputEvidence(api, rc, spend.section.Hashes, spend.section.Count), opened.ExitRecords())
	delivered := w.Deliver(api, envelope, keyEscrow, c.Outputs, opened, stream)
	c.screen(api, rc, g, policy.Spend{Senders: spend.senders, Inputs: spend.section.Slots}, opened.Slots)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, stream, opened, delivered, spend.signers)))
	return nil
}

func (c *ConfidentialTransferCircuit) assertRail(api frontend.API) {
	for _, bit := range []frontend.Variable{c.InProof, c.Delegate} {
		api.AssertIsBoolean(bit)
	}
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.InProof})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, c.InProof), V: c.Sender})
}

func (c *ConfidentialTransferCircuit) decodeLayout(api frontend.API) frontend.Variable {
	keyEscrow := audit.DecodeLayout(api, c.Layout, audit.LayoutEscrow, 0).Flag(audit.LayoutEscrow)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: api.Sub(1, keyEscrow)})
	return keyEscrow
}

type confidentialSpend struct {
	section InputSection
	signers SignerSet
	senders []frontend.Variable
}

// spendInputs holds every live input to the rail's owner predicate, a mismatch would let a rail spend a note its authorization never covered.
func (c *ConfidentialTransferCircuit) spendInputs(api frontend.API, screened frontend.Variable) confidentialSpend {
	section := OpenInputs(api, c.Inputs, c.InputCount)
	section.AssertRingNotes(api, c.RingProgramID)
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	ownerRail := api.Add(c.InProof, c.Delegate)
	signerRail := api.Sub(1, ownerRail)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: ownerRail, V: c.SignerCount})
	// Under a policy the set holds an owner to screen, a public-funded transfer included.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(screened, signerRail), V: signers.Count.OneHot[0]})
	signers.AssertAtMost(api, screened, screenedOwners)
	railOwner := api.Select(c.Delegate, c.SenderPkHash, c.Sender)
	section.AssertOwnedBy(api, ownerRail, railOwner)
	for _, slot := range section.Slots {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(signerRail, slot.Utxo), V: signers.missing(api, slot.OwnerPkHash)})
	}
	senders := make([]frontend.Variable, screenedOwners)
	senders[0] = api.Select(ownerRail, railOwner, signers.At(0))
	for j := 1; j < screenedOwners; j++ {
		senders[j] = signers.At(j)
	}
	return confidentialSpend{section: section, signers: signers, senders: senders}
}

// statement is the confidential transfer preimage, mirrored by TransferStatement::elements under TransferFamily::Confidential in program-libs/interface/src/proof/statement.rs.
func (c *ConfidentialTransferCircuit) statement(e audit.Envelope, w audit.AuditWires, stream audit.Stream, opened audit.Opened, d audit.Delivered, signers SignerSet) []frontend.Variable {
	fields := slices.Concat(e.Head(w, stream, shared.TransferStatementDomain), []frontend.Variable{
		c.InProof, c.Delegate, c.Exempt, c.ApprovalRequired,
		c.OutputCount,
		opened.OutputChain, d.OutputCiphertextChain, d.RecipientKeyChain,
		c.InputCount, opened.ExitsBitmap, c.PrivateTxHash,
		c.Sender,
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, c.Recipients, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash))
}
