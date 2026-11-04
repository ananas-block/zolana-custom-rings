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

// ConfidentialShape sizes a key, Inputs the slots every rail opens and the signers it can bind, Owners the rows, FullOpenings a spend of default-ring notes.
type ConfidentialShape struct {
	Inputs, Outputs, Withdrawals, Owners int
	FullOpenings                         bool
}

// ConfidentialBases and EntryBases mirror CONFIDENTIAL_TRANSFER_SHAPES and ENTRY_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs, each takes every owner capacity.
var (
	ConfidentialBases = [...]ConfidentialShape{
		{Inputs: 24, Outputs: 2, Withdrawals: 4},
		{Inputs: 24, Outputs: 2, Withdrawals: 32},
		{Inputs: 24, Outputs: 4, Withdrawals: 4},
		{Inputs: 24, Outputs: 4, Withdrawals: 32},
		{Inputs: 16, Outputs: 8, Withdrawals: 4},
		{Inputs: 16, Outputs: 8, Withdrawals: 32},
		{Inputs: 5, Outputs: 16, Withdrawals: 8},
	}
	ConfidentialShapes = confidentialKeys(ConfidentialBases[:], false)
	// ConfidentialEntryShapes spend a default-ring note on the signer rails.
	ConfidentialEntryShapes = confidentialKeys(entryBases(), true)
)

func confidentialKeys(bases []ConfidentialShape, entry bool) []ConfidentialShape {
	var keys []ConfidentialShape
	for _, base := range bases {
		for _, owners := range ownerCapacities(base.Inputs) {
			base.Owners, base.FullOpenings = owners, entry
			keys = append(keys, base)
		}
	}
	return keys
}

func entryBases() []ConfidentialShape {
	bases := make([]ConfidentialShape, len(EntryBases))
	for i, base := range EntryBases {
		bases[i] = ConfidentialShape{Inputs: base.InputClass, Outputs: base.Outputs, Withdrawals: base.Withdrawals}
	}
	return bases
}

func (s ConfidentialShape) String() string {
	family := "confidential"
	if s.FullOpenings {
		family = "confidential_entry"
	}
	return fmt.Sprintf("custom_ring_transfer_%s_%d_in%d_w%d_s%d", family, s.Outputs, s.Inputs, s.Withdrawals, s.Owners)
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
	Sender      frontend.Variable
	SignerCount frontend.Variable
	// Signers is the program's owner signer run, zero past SignerCount.
	Signers []frontend.Variable
	// Rows are the distinct live input owners, ascending with zero rows last.
	Rows []frontend.Variable
	policy.Tracking
	screenedPolicy
}

func NewConfidentialTransferCircuit(shape ConfidentialShape) (*ConfidentialTransferCircuit, error) {
	if !slices.Contains(ConfidentialShapes, shape) && !slices.Contains(ConfidentialEntryShapes, shape) {
		return nil, fmt.Errorf("transfer: unsupported confidential shape %+v, want one of %v or %v", shape, ConfidentialShapes, ConfidentialEntryShapes)
	}
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.Owners}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	tracking, err := policy.NewTracking(shape.Owners, shape.Outputs)
	if err != nil {
		return nil, err
	}
	return &ConfidentialTransferCircuit{
		Shape:          shape,
		Rows:           make([]frontend.Variable, shape.Owners),
		Tracking:       tracking,
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
		shared.ValidateLength("transfer", "owner row", len(c.Rows), c.Shape.Owners),
		c.ValidateTracking(c.Shape.Owners, c.Shape.Outputs),
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
	c.bypassPolicy(api, c.Delegate)
	spend := c.spendInputs(api)
	tracking := c.OpenTracking(api)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, tracking)
	rows.AssertInputOwners(api, InputRail{Delegate: c.Delegate, Hidden: 0, HiddenOwner: 0}, spend.section.Slots)
	AssertOutputOwners(api, tracking, opened.Slots, c.OutputEntries)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, spend.section.Hashes), opened.Slots)
	stream := w.SealStream(api, audit.ConfidentialRanges(c.Shape.Inputs, c.Shape.Outputs), audit.InputEvidence(api, rc, spend.section.Hashes, spend.section.Count), opened.ExitRecords())
	delivered := w.Deliver(api, envelope, keyEscrow, c.Outputs, opened, stream)
	c.screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: spend.section.Slots}, opened.Slots)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, stream, opened, delivered, spend.signers)))
	return nil
}

func (c *ConfidentialTransferCircuit) assertRail(api frontend.API) {
	for _, bit := range []frontend.Variable{c.InProof, c.Delegate, c.ApprovalRequired} {
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
}

// spendInputs holds every live input to a signer or the in-proof owner, the delegate proves no owner authorization.
func (c *ConfidentialTransferCircuit) spendInputs(api frontend.API) confidentialSpend {
	section := OpenInputs(api, c.Inputs, c.InputCount)
	section.AssertRingNotes(api, c.RingProgramID, c.Shape.FullOpenings)
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.SignerCount})
	signers.AssertOwners(api, section, api.Sub(1, c.Delegate), c.Sender)
	return confidentialSpend{section: section, signers: signers}
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
		c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.TrackingRoot,
	}, c.Recipients, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash))
}
