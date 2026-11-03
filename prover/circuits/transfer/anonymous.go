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
	InputClass, Outputs, Withdrawals int
	FullOpenings                     bool
	Records                          policy.RecordPoolShape
}

func (s AnonymousShape) audit() audit.AnonymousAuditShape {
	return audit.AnonymousAuditShape{InputClass: s.InputClass, Outputs: s.Outputs, FullOpenings: s.FullOpenings}
}

func (s AnonymousShape) keyed() AnonymousShape {
	return AnonymousShape{InputClass: s.InputClass, Outputs: s.Outputs, Withdrawals: s.Withdrawals, FullOpenings: s.FullOpenings}
}

// AnonymousShapes are the commitment keys and EntryShapes the entry keys, mirrored by ANONYMOUS_TRANSFER_SHAPES and ENTRY_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var (
	AnonymousShapes = [...]AnonymousShape{
		{InputClass: 24, Outputs: 2, Withdrawals: 4},
		{InputClass: 24, Outputs: 2, Withdrawals: 32},
		{InputClass: 16, Outputs: 4, Withdrawals: 4},
		{InputClass: 16, Outputs: 4, Withdrawals: 32},
		{InputClass: 5, Outputs: 8, Withdrawals: 24},
	}
	EntryShapes = [...]AnonymousShape{
		{InputClass: 8, Outputs: 2, Withdrawals: 4, FullOpenings: true},
		{InputClass: 8, Outputs: 4, Withdrawals: 4, FullOpenings: true},
		{InputClass: 2, Outputs: 8, Withdrawals: 4, FullOpenings: true},
	}
)

func (s AnonymousShape) String() string {
	family := "anonymous"
	if s.FullOpenings {
		family = "anonymous_entry"
	}
	return fmt.Sprintf("custom_ring_transfer_%s_%d_in%d_w%d", family, s.Outputs, s.InputClass, s.Withdrawals)
}

type AnonymousTransferCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Shape           AnonymousShape    `gnark:"-"`
	auditStatementWires
	OutputCount frontend.Variable
	Outputs     []audit.AnonymousOutputWires
	// SenderKey is the hidden owner's Ed25519 key on an entry key, a commitment key carries none.
	SenderKey  []frontend.Variable
	InputCount frontend.Variable
	Inputs     []shared.UtxoWires
	transactionBinding
	// PartyIdentities are payer, configured co-signer and withdrawal owner, an absent party is zero.
	PartyIdentities [3]frontend.Variable
	SignerCount     frontend.Variable
	// Signers is the public co-owners, zero past SignerCount, no slot on an entry key.
	Signers []frontend.Variable
	audit.SenderAddress
	// The program's reply region digest, zero without one, bound by the statement alone.
	ReplyDigest frontend.Variable
	screenedPolicy
}

func (s AnonymousShape) signerSlots() int {
	if s.FullOpenings {
		return 0
	}
	return s.InputClass
}

func (s AnonymousShape) screenedOwners() int {
	if s.FullOpenings {
		return 1
	}
	return screenedOwners
}

func NewAnonymousTransferCircuit(shape AnonymousShape) (*AnonymousTransferCircuit, error) {
	keyed := shape.keyed()
	if !slices.Contains(AnonymousShapes[:], keyed) && !slices.Contains(EntryShapes[:], keyed) {
		return nil, fmt.Errorf("transfer: unsupported anonymous shape %+v, want one of %v or %v", keyed, AnonymousShapes, EntryShapes)
	}
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.screenedOwners()}.Inputs(), shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	senderKey := 0
	if shape.FullOpenings {
		senderKey = 32
	}
	return &AnonymousTransferCircuit{
		Shape:          shape,
		Outputs:        make([]audit.AnonymousOutputWires, shape.Outputs),
		SenderKey:      make([]frontend.Variable, senderKey),
		Inputs:         make([]shared.UtxoWires, shape.InputClass),
		Signers:        make([]frontend.Variable, shape.signerSlots()),
		screenedPolicy: screenedPolicy{Policy: p},
	}, nil
}

func (c *AnonymousTransferCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), c.Shape.InputClass),
		shared.ValidateLength("transfer", "signer", len(c.Signers), c.Shape.signerSlots()),
		shared.ValidateLength("transfer", "escrow hash", len(c.CtHashes), c.Shape.Outputs),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), c.Shape.Withdrawals),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	w := c.auditWires(c.RingProgramID)
	envelope := w.OpenEnvelope(api, rc)
	c.decodeLayout(api)
	opened := audit.OpenSlots(api, rc, w, envelope, c.Outputs, c.OutputCount)
	// Delivery holds the own pool active on every anonymous transfer, the program's RootRead loads a real own root.
	g := c.gates(api, policy.Rail{KeyEscrow: 0, Delegate: 0, Published: 0, Delivery: 1})
	spent := AnonymousInputs{Inputs: c.Inputs, InputCount: c.InputCount, Signers: c.Signers, SignerCount: c.SignerCount, SenderKey: c.SenderKey, RingProgramID: c.RingProgramID}.Spend(api, rc, g.Screened)
	shared.AssertAnonymousParties(api, spent.Sender, c.PartyIdentities)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, spent.Section.Hashes), opened.Slots)
	screening := c.screen(api, rc, g, policy.Spend{Senders: spent.Senders, Inputs: spent.Section.Slots}, opened.Slots)
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
}

type AnonymousSpend struct {
	Section  InputSection
	Signers  SignerSet
	Sender   frontend.Variable
	Senders  []frontend.Variable
	Evidence audit.Evidence
}

// Spend holds every live input to the sender or a public co-owner on a commitment key, to the one key owner on an entry key.
func (a AnonymousInputs) Spend(api frontend.API, rc frontend.Rangechecker, screened frontend.Variable) AnonymousSpend {
	section := OpenInputs(api, a.Inputs, a.InputCount)
	signers := OpenSigners(api, a.Signers, a.SignerCount)
	if len(a.SenderKey) != 0 {
		// SolanaOwnerIdentity bounds the sender key the evidence head reads.
		sender := gadget.SolanaOwnerIdentity(api, [32]frontend.Variable(a.SenderKey))
		section.AssertOwnedBy(api, 1, sender)
		return AnonymousSpend{Section: section, Signers: signers, Sender: sender, Senders: []frontend.Variable{sender}, Evidence: audit.EntryEvidence(api, rc, section.Slots, section.Hashes, a.SenderKey, section.Count)}
	}
	section.AssertRingNotes(api, a.RingProgramID)
	sender := section.Slots[0].OwnerPkHash
	// Input 0 is live and hidden, SPP's HiddenOwnerSigners needs a hidden owner.
	api.AssertIsEqual(section.Slots[0].Utxo, 1)
	api.AssertIsEqual(api.IsZero(signers.missing(api, sender)), 0)
	signers.AssertAtMost(api, screened, screenedOwners-1)
	for _, slot := range section.Slots {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(slot.Utxo, api.Sub(slot.OwnerPkHash, sender)), V: signers.missing(api, slot.OwnerPkHash)})
	}
	senders := make([]frontend.Variable, screenedOwners)
	senders[0] = sender
	for j := 1; j < screenedOwners; j++ {
		senders[j] = signers.At(j - 1)
	}
	return AnonymousSpend{Section: section, Signers: signers, Sender: sender, Senders: senders, Evidence: audit.InputEvidence(api, rc, section.Hashes, section.Count)}
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
		c.Exempt, c.ApprovalRequired,
		c.OutputCount,
		opened.OutputChain, outputCiphertextChain, d.RecipientBodyChain, d.RecipientTagChain,
		d.ChangeBitmap,
		d.SenderBundleDigest,
		c.InputCount, opened.ExitsBitmap, c.PrivateTxHash,
		c.PartyIdentities[0], c.PartyIdentities[1], c.PartyIdentities[2],
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash, c.ReplyDigest))
}
