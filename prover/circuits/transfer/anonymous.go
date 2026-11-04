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

// AnonymousShape sizes a key, FullOpenings the entry layout of a spend of default-ring notes.
type AnonymousShape struct {
	InputClass, Outputs, Withdrawals, Owners int
	FullOpenings                             bool
}

func (s AnonymousShape) audit() audit.AnonymousAuditShape {
	return audit.AnonymousAuditShape{InputClass: s.InputClass, Outputs: s.Outputs, FullOpenings: s.FullOpenings}
}

// AnonymousBases and EntryBases mirror ANONYMOUS_TRANSFER_SHAPES and ENTRY_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs, each takes every owner capacity.
var (
	AnonymousBases = [...]AnonymousShape{
		{InputClass: 24, Outputs: 2, Withdrawals: 4},
		{InputClass: 24, Outputs: 2, Withdrawals: 32},
		{InputClass: 16, Outputs: 4, Withdrawals: 4},
		{InputClass: 16, Outputs: 4, Withdrawals: 32},
		{InputClass: 5, Outputs: 8, Withdrawals: 24},
	}
	EntryBases = [...]AnonymousShape{
		{InputClass: 8, Outputs: 2, Withdrawals: 4, FullOpenings: true},
		{InputClass: 8, Outputs: 4, Withdrawals: 4, FullOpenings: true},
		{InputClass: 2, Outputs: 8, Withdrawals: 4, FullOpenings: true},
	}
	AnonymousShapes = anonymousKeys(AnonymousBases[:])
	EntryShapes     = anonymousKeys(EntryBases[:])
)

func anonymousKeys(bases []AnonymousShape) []AnonymousShape {
	var keys []AnonymousShape
	for _, base := range bases {
		for _, owners := range ownerCapacities(base.InputClass) {
			base.Owners = owners
			keys = append(keys, base)
		}
	}
	return keys
}

func (s AnonymousShape) String() string {
	family := "anonymous"
	if s.FullOpenings {
		family = "anonymous_entry"
	}
	return fmt.Sprintf("custom_ring_transfer_%s_%d_in%d_w%d_s%d", family, s.Outputs, s.InputClass, s.Withdrawals, s.Owners)
}

type AnonymousTransferCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Shape           AnonymousShape    `gnark:"-"`
	auditStatementWires
	// PublicOwners names the rail where every live owner is a published signer, Delegate the authority rail, neither the hidden sender rail.
	PublicOwners, Delegate frontend.Variable
	OutputCount            frontend.Variable
	Outputs                []audit.AnonymousOutputWires
	// SenderKey is the hidden owner's Ed25519 key on an entry key, a commitment key carries none.
	SenderKey  []frontend.Variable
	InputCount frontend.Variable
	Inputs     []shared.UtxoWires
	transactionBinding
	// PartyIdentities are payer, five co-signers and exit destination, an absent party is zero.
	PartyIdentities [shared.AnonymousParties]frontend.Variable
	SignerCount     frontend.Variable
	// Signers is the public co-owners, zero past SignerCount.
	Signers []frontend.Variable
	// Rows are the distinct live input owners, ascending with zero rows last.
	Rows []frontend.Variable
	policy.Tracking
	audit.SenderAddress
	// The program's reply region digest, zero without one, bound by the statement alone.
	ReplyDigest frontend.Variable
	screenedPolicy
}

func NewAnonymousTransferCircuit(shape AnonymousShape) (*AnonymousTransferCircuit, error) {
	if !slices.Contains(AnonymousShapes, shape) && !slices.Contains(EntryShapes, shape) {
		return nil, fmt.Errorf("transfer: unsupported anonymous shape %+v, want one of %v or %v", shape, AnonymousShapes, EntryShapes)
	}
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.Owners}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	senderKey := 0
	if shape.FullOpenings {
		senderKey = 32
	}
	tracking, err := policy.NewTracking(shape.Owners, shape.Outputs)
	if err != nil {
		return nil, err
	}
	return &AnonymousTransferCircuit{
		Shape:          shape,
		Rows:           make([]frontend.Variable, shape.Owners),
		Tracking:       tracking,
		Outputs:        make([]audit.AnonymousOutputWires, shape.Outputs),
		SenderKey:      make([]frontend.Variable, senderKey),
		Inputs:         make([]shared.UtxoWires, shape.InputClass),
		Signers:        make([]frontend.Variable, shape.InputClass),
		screenedPolicy: screenedPolicy{Policy: p},
	}, nil
}

func (c *AnonymousTransferCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), c.Shape.InputClass),
		shared.ValidateLength("transfer", "signer", len(c.Signers), c.Shape.InputClass),
		shared.ValidateLength("transfer", "escrow hash", len(c.CtHashes), c.Shape.Outputs),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), c.Shape.Withdrawals),
		shared.ValidateLength("transfer", "owner row", len(c.Rows), c.Shape.Owners),
		c.ValidateTracking(c.Shape.Owners, c.Shape.Outputs),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	w := c.auditWires(c.RingProgramID)
	envelope := w.OpenEnvelope(api, rc)
	c.decodeLayout(api)
	opened := audit.OpenSlots(api, rc, w, envelope, c.Outputs, c.OutputCount)
	// Delivery holds the own pool active on every anonymous transfer, the program's RootRead loads a real own root.
	g := c.gates(api, policy.Rail{KeyEscrow: 0, Delegate: c.Delegate, Published: 0, Delivery: 1})
	c.bypassPolicy(api, c.Delegate)
	spent := AnonymousInputs{Inputs: c.Inputs, InputCount: c.InputCount, Signers: c.Signers, SignerCount: c.SignerCount, SenderKey: c.SenderKey, RingProgramID: c.RingProgramID, PublicOwners: c.PublicOwners, Delegate: c.Delegate}.Spend(api, rc)
	shared.AssertAnonymousParties(api, spent.Sender, c.PartyIdentities[:])
	tracking := c.OpenTracking(api)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, tracking)
	rows.AssertInputOwners(api, InputRail{Delegate: c.Delegate, Hidden: spent.Hidden, HiddenOwner: spent.Sender}, spent.Section.Slots)
	AssertOutputOwners(api, tracking, opened.Slots, c.OutputEntries)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, spent.Section.Hashes), opened.Slots)
	screening := c.screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: spent.Section.Slots}, opened.Slots)
	delivery := w.DeliverRecipients(api, rc, envelope, c.Outputs, opened, spent.Sender, c.SenderAddress, audit.AddressRows{Sender: screening.SenderAddress, Owners: screening.OwnerAddresses})
	stream := w.SealStream(api, c.Shape.audit().Ranges(), spent.Evidence, opened.AnonymousRecords(api, c.Outputs))
	ciphertextChain := opened.RecordChain(api, stream)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, stream, opened, ciphertextChain, delivery, spent.Signers)))
	return nil
}

// A nonempty SenderKey names the entry layout.
type AnonymousInputs struct {
	Inputs        []shared.UtxoWires
	InputCount    frontend.Variable
	Signers       []frontend.Variable
	SignerCount   frontend.Variable
	SenderKey     []frontend.Variable
	RingProgramID frontend.Variable
	// Both clear names the hidden sender rail, the program sets each and selects SPP's circuit from them.
	PublicOwners, Delegate frontend.Variable
}

type AnonymousSpend struct {
	Section InputSection
	Signers SignerSet
	// Hidden is set on the hidden sender rail, Sender zero off it.
	Hidden, Sender frontend.Variable
	Evidence       audit.Evidence
}

// Spend holds every live input to the hidden sender or a public co-owner, to a public signer on the public owner rail, and the delegate proves no owner authorization.
func (a AnonymousInputs) Spend(api frontend.API, rc frontend.Rangechecker) AnonymousSpend {
	api.AssertIsBoolean(a.PublicOwners)
	api.AssertIsBoolean(a.Delegate)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: a.PublicOwners, V: a.Delegate})
	hidden := api.Sub(1, api.Add(a.PublicOwners, a.Delegate))
	section := OpenInputs(api, a.Inputs, a.InputCount)
	section.AssertRingNotes(api, a.RingProgramID, len(a.SenderKey) != 0)
	signers := OpenSigners(api, a.Signers, a.SignerCount)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: a.Delegate, V: a.SignerCount})
	sender := api.Mul(hidden, section.Slots[0].OwnerPkHash)
	// Input 0 is live and hidden, SPP's HiddenOwnerSigners needs a hidden owner.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.Sub(1, section.Slots[0].Utxo)})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(signers.missing(api, sender))})
	signers.AssertOwners(api, section, api.Sub(1, a.Delegate), sender)
	evidence := audit.InputEvidence(api, rc, section.Hashes, section.Count)
	if len(a.SenderKey) != 0 {
		evidence = audit.EntryEvidence(api, rc, section.Slots, section.Hashes, a.SenderKey, section.Count)
	}
	return AnonymousSpend{Section: section, Signers: signers, Hidden: hidden, Sender: sender, Evidence: evidence}
}

func (c *AnonymousTransferCircuit) decodeLayout(api frontend.API) {
	fixed := 0
	if c.Shape.FullOpenings {
		fixed = audit.LayoutFullOpenings
	}
	audit.DecodeLayout(api, c.Layout, 0, fixed)
}

// statement is the anonymous transfer preimage, mirrored by TransferStatement::elements under TransferFamily::Anonymous in program-libs/interface/src/proof/statement.rs.
func (c *AnonymousTransferCircuit) statement(e audit.Envelope, w audit.AuditWires, stream audit.Stream, opened audit.Opened, outputCiphertextChain frontend.Variable, d audit.RecipientDelivery, signers SignerSet) []frontend.Variable {
	fields := slices.Concat(e.Head(w, stream, shared.TransferStatementDomain), []frontend.Variable{
		c.PublicOwners, c.Delegate, c.Exempt, c.ApprovalRequired,
		c.OutputCount,
		opened.OutputChain, outputCiphertextChain, d.RecipientBodyChain, d.RecipientTagChain,
		d.ChangeBitmap,
		d.SenderBundleDigest,
		c.InputCount, opened.ExitsBitmap, c.PrivateTxHash,
	}, c.PartyIdentities[:], []frontend.Variable{
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.TrackingRoot,
	}, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash, c.ReplyDigest))
}
