// Package transfer proves a ring transfer's audit, policy and owner predicates in one proof.
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

// Shape sizes a key, Inputs also bounds the signers it can bind.
type Shape struct {
	Inputs, Outputs, Withdrawals, Owners int
	Entry                                bool
	// Wide fits a salted and a public record per owner.
	Wide bool
}

// Shapes mirrors TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var Shapes = [...]Shape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 4, Owners: 4},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5},
	{Inputs: 24, Outputs: 8, Withdrawals: 32, Owners: 24, Wide: true},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5, Wide: true},
	{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true},
	{Inputs: 2, Outputs: 8, Withdrawals: 4, Owners: 2, Entry: true, Wide: true},
}

func (s Shape) String() string {
	family := "transfer"
	switch {
	case s.Entry:
		family = "transfer_entry"
	case s.Wide:
		family = "transfer_wide"
	}
	return fmt.Sprintf("custom_ring_%s_%d_in%d_w%d_s%d", family, s.Outputs, s.Inputs, s.Withdrawals, s.Owners)
}

// TransferCircuit serves every rail, a clear bit set is the signer rail.
type TransferCircuit struct {
	Shape Shape `gnark:"-"`
	// Delegate is the authority rail.
	InProof, Hidden, Delegate frontend.Variable
	Sender                    frontend.Variable
	// PartyIdentities are an anonymous frame's public parties, an absent party is zero.
	PartyIdentities [shared.AnonymousParties]frontend.Variable
	Sections
}

func NewTransferCircuit(shape Shape) (*TransferCircuit, error) {
	if !slices.Contains(Shapes[:], shape) {
		return nil, fmt.Errorf("unsupported transfer shape %+v, want one of %v", shape, Shapes)
	}
	wires, err := NewSections(shape)
	if err != nil {
		return nil, err
	}
	return &TransferCircuit{Shape: shape, Sections: wires}, nil
}

// Sections are the wires every transfer key reads, the rail fills the rest of its statement.
type Sections struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	FirstNullifier  frontend.Variable
	TxViewingSk     [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
	Salt            [16]frontend.Variable
	Layout          frontend.Variable
	OutputCount     frontend.Variable
	Outputs         []audit.OutputWires
	InputCount      frontend.Variable
	Inputs          []shared.UtxoWires
	// Entries open default-ring inputs to the auditor, none off an entry key.
	Entries []audit.EntryWires
	transactionBinding
	SignerCount frontend.Variable
	// Signers is the program's owner signer run, zero past SignerCount.
	Signers []frontend.Variable
	// Rows are the distinct live input owners, ascending with zero rows last.
	Rows []frontend.Variable
	policy.Tracking
	// ApprovalMask is the proven approval bits, the program demands their co-signers.
	ApprovalMask frontend.Variable
	policy.Policy
}

// ownerAddresses mirrors OWNER_ADDRESSES in key_catalog.rs, a v1 transaction's 64 addresses less SPP's 4 and the ring's 6.
const ownerAddresses = 64 - 4 - 6

// publicOwners is the distinct signers and legs one transaction can name, each signer also takes a nullifier PDA.
func (s Shape) publicOwners() int {
	return min(s.Owners, (ownerAddresses-s.Withdrawals)/2) + s.Withdrawals
}

func (s Shape) trackedWithdrawals() int {
	if !s.Wide {
		return 0
	}
	return s.publicOwners() - s.Owners
}

// saltedKeys fits a public and a salted record per distinct owner in one pool.
func (s Shape) saltedKeys() int {
	if !s.Wide {
		return 0
	}
	return 2*s.publicOwners() + s.Outputs - s.Owners - s.Withdrawals
}

// Stream compiles the tails into every key, a clear has_data transmits none.
func (s Shape) Stream() audit.StreamShape {
	return audit.StreamShape{InputClass: s.Inputs, Outputs: s.Outputs, Entry: s.Entry, Data: true}
}

func (s Shape) entries() int {
	if s.Entry {
		return s.Inputs
	}
	return 0
}

func NewSections(shape Shape) (Sections, error) {
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.Owners, SaltedKeys: shape.saltedKeys()}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return Sections{}, err
	}
	tracking, err := policy.NewTracking(shape.Owners, shape.Outputs, shape.trackedWithdrawals())
	if err != nil {
		return Sections{}, err
	}
	return Sections{
		Outputs:  make([]audit.OutputWires, shape.Outputs),
		Inputs:   make([]shared.UtxoWires, shape.Inputs),
		Entries:  make([]audit.EntryWires, shape.entries()),
		Signers:  make([]frontend.Variable, shape.Inputs),
		Rows:     make([]frontend.Variable, shape.Owners),
		Tracking: tracking,
		Policy:   p,
	}, nil
}

func (c *Sections) validate(shape Shape) error {
	return errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), shape.Inputs),
		shared.ValidateLength("transfer", "entry", len(c.Entries), shape.entries()),
		shared.ValidateLength("transfer", "signer", len(c.Signers), shape.Inputs),
		shared.ValidateLength("transfer", "owner row", len(c.Rows), shape.Owners),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), shape.Withdrawals),
		c.ValidateTracking(shape.Owners, shape.Outputs, shape.trackedWithdrawals()),
	)
}

// Define runs every section once, the rail bits alone tell the rails apart.
func (c *TransferCircuit) Define(api frontend.API) error {
	if err := c.validate(c.Shape); err != nil {
		return err
	}
	c.assertRail(api)
	rc := rangecheck.New(api)
	w := audit.AuditWires{FirstNullifier: c.FirstNullifier, RingProgramID: c.RingProgramID, TxViewingSk: c.TxViewingSk, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Salt: c.Salt, Layout: c.Layout}
	stream := c.Shape.Stream()
	layout := stream.DecodeLayout(api, c.Layout)
	envelope := w.OpenEnvelope(api, rc)
	opened := audit.OpenSlots(api, rc, w, envelope, stream, layout, c.Outputs, c.OutputCount)
	section := OpenInputs(api, c.Inputs, c.InputCount)
	section.AssertRingNotes(api, c.RingProgramID, c.Shape.Entry)
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	// The delegate signs for every owner, a published run would name a victim.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.SignerCount})
	hiddenOwner := c.hiddenOwner(api, section, signers)
	signers.AssertOwners(api, section, api.Sub(1, c.Delegate), api.Add(hiddenOwner, c.Sender))
	tracking := c.OpenTracking(api)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, tracking)
	rows.AssertInputOwners(api, InputRail{Delegate: c.Delegate, Hidden: c.Hidden, HiddenOwner: hiddenOwner}, section.Slots)
	AssertOutputOwners(api, tracking, opened.Slots, c.OutputEntries)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, section.Hashes), opened.Slots)
	c.assertBypass(api, c.Delegate)
	// A ring with an own policy registry reads its root on every rail but the delegate's, no prover bit clears the thresholds.
	g := policy.Rail{ThresholdsActive: ringgadget.IsNonZero(api, c.OwnRoot), Delegate: c.Delegate}.Gates(api, c.PolicyHash)
	screening := c.Screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: section.Slots, Tracking: tracking}, opened.Slots)
	api.AssertIsEqual(c.ApprovalMask, screening.ApprovalMask)
	sealed := w.SealStream(api, rc, stream, opened, audit.SpentInputs{Slots: section.Slots, Count: section.Count, Entries: c.Entries})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, sealed, opened, signers)))
	return nil
}

// assertRail holds the bits to one rail, only the in-proof rail names a public sender.
func (c *TransferCircuit) assertRail(api frontend.API) {
	api.AssertIsBoolean(c.InProof)
	api.AssertIsBoolean(c.Hidden)
	api.AssertIsBoolean(c.Delegate)
	api.AssertIsBoolean(api.Add(c.InProof, c.Hidden, c.Delegate))
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, c.InProof), V: c.Sender})
}

// hiddenOwner reads input 0, zero on every rail with no owner to hide.
func (c *TransferCircuit) hiddenOwner(api frontend.API, section InputSection, signers SignerSet) frontend.Variable {
	owner := api.Mul(c.Hidden, section.Slots[0].OwnerPkHash)
	// SPP's HiddenOwnerSigners needs a live hidden owner, one in the published run would name it.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Hidden, V: api.Sub(1, section.Slots[0].Utxo)})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Hidden, V: api.IsZero(signers.missing(api, owner))})
	shared.AssertAnonymousParties(api, owner, c.PartyIdentities[:])
	return owner
}

// assertBypass holds the authority rail's statement off every policy registry, a curator's update then cannot fail a delegate's proof.
func (c *Sections) assertBypass(api frontend.API, delegate frontend.Variable) {
	for _, value := range []frontend.Variable{c.PolicyHash, c.OwnRoot, c.CuratorRoot} {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: delegate, V: value})
	}
}

// statement mirrors TransferStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *TransferCircuit) statement(e audit.Envelope, w audit.AuditWires, s audit.Stream, opened audit.Opened, signers SignerSet) []frontend.Variable {
	fields := slices.Concat(e.Head(w, s, shared.TransferStatementDomain), []frontend.Variable{
		c.InProof, c.Hidden, c.Delegate, c.ApprovalMask, s.NoSpend,
		c.OutputCount, opened.OutputChain, s.RecordChain, s.TailChain,
		c.InputCount, c.PrivateTxHash, c.Sender,
	}, c.PartyIdentities[:], []frontend.Variable{
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.TrackingRoot,
	}, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]), []frontend.Variable{c.WithdrawalHash})
	return closeStatement(fields)
}

// transactionBinding is SPP's private transaction hash and its blinding, the proof reopens the hash over the slots the audit opened.
type transactionBinding struct {
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	// AddressChain is SPP's chain of address slot nullifiers, zero without one, SPP alone reads the slots.
	AddressChain frontend.Variable
}

// bindTransaction holds PrivateTxHash to Poseidon(input chain, output chain, address chain, blinding), a note called an address would leave the input chain SPP hashed.
func (b transactionBinding) bindTransaction(api frontend.API, inputChain frontend.Variable, outputs []shared.Output) {
	outputChain := gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs))
	api.AssertIsEqual(b.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, b.AddressChain, b.PrivateTxBlinding}))
}

// closeStatement binds the element count and the nonzero version last, a statement of another length or layout hashes apart.
func closeStatement(fields []frontend.Variable) []frontend.Variable {
	return append(fields, len(fields)+2, shared.TransferStatementVersion)
}

func publicSlots(assets, amounts, gross []frontend.Variable) []frontend.Variable {
	fields := make([]frontend.Variable, 0, 3*len(assets))
	for k := range assets {
		fields = append(fields, assets[k], amounts[k], gross[k])
	}
	return fields
}
