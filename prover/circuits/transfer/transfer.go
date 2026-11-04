// Package transfer proves a ring transfer's audit, policy and owner predicates in one proof.
package transfer

import (
	"errors"
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

const (
	// smallOwners keys the rows nearly every transfer needs, a row costs constraints on every proof of its key.
	smallOwners = 4
	// ownerAddresses mirrors the bound of TransferAddresses in program-libs/interface/src/proof/key_catalog.rs, a v1 transaction's 64 addresses less SPP's 4 and the ring's 6.
	ownerAddresses = 64 - 4 - 6
)

// privateRows opens every owner and four withdrawal owners, a transaction past them fails closed.
func privateRows(owners, outputs, withdrawals int) int {
	return owners + outputs + min(withdrawals, smallOwners)
}

// ownerCapacities are the row counts a key of inputs input slots takes, ascending, mirrored by TransferShape::owners.
func ownerCapacities(inputs int) []int {
	small, full := min(smallOwners, inputs), min(inputs, ownerAddresses-inputs)
	if full <= small {
		return []int{small}
	}
	return []int{small, full}
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

type SectionsShape struct {
	inputs, outputs, withdrawals, owners, private int
	entry, data                                   bool
}

func (s SectionsShape) stream() audit.StreamShape {
	return audit.StreamShape{InputClass: s.inputs, Outputs: s.outputs, Entry: s.entry, Data: s.data}
}

func NewSections(shape SectionsShape) (Sections, error) {
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.outputs, Withdrawals: shape.withdrawals, Senders: shape.owners, Private: shape.private}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return Sections{}, err
	}
	tracking, err := policy.NewTracking(shape.owners, shape.outputs, shape.private)
	if err != nil {
		return Sections{}, err
	}
	entries := 0
	if shape.entry {
		entries = shape.inputs
	}
	return Sections{
		Outputs:  make([]audit.OutputWires, shape.outputs),
		Inputs:   make([]shared.UtxoWires, shape.inputs),
		Entries:  make([]audit.EntryWires, entries),
		Signers:  make([]frontend.Variable, shape.inputs),
		Rows:     make([]frontend.Variable, shape.owners),
		Tracking: tracking,
		Policy:   p,
	}, nil
}

func (c *Sections) validate(shape SectionsShape) error {
	entries := 0
	if shape.entry {
		entries = shape.inputs
	}
	return errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), shape.outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), shape.inputs),
		shared.ValidateLength("transfer", "entry", len(c.Entries), entries),
		shared.ValidateLength("transfer", "signer", len(c.Signers), shape.inputs),
		shared.ValidateLength("transfer", "owner row", len(c.Rows), shape.owners),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), shape.withdrawals),
		c.ValidateTracking(shape.owners, shape.outputs, shape.private),
	)
}

// rail is what one family's statement fixes about who authorizes the spend.
type rail struct {
	// bits are the statement's two rail bits, cells its sender or party identities.
	bits  [2]frontend.Variable
	cells []frontend.Variable
	// delegate is the authority rail, the configured delegate signs in place of every owner.
	delegate frontend.Variable
	// private names an owner no signer account shows, hidden set when spending under it must stay private.
	private func(api frontend.API, section InputSection, signers SignerSet) (owner, hidden frontend.Variable)
}

// prove runs every section once, each family differs by its rail alone.
func (c *Sections) prove(api frontend.API, shape SectionsShape, r rail) {
	rc := rangecheck.New(api)
	w := audit.AuditWires{FirstNullifier: c.FirstNullifier, RingProgramID: c.RingProgramID, TxViewingSk: c.TxViewingSk, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Salt: c.Salt, Layout: c.Layout}
	stream := shape.stream()
	layout := stream.DecodeLayout(api, c.Layout)
	envelope := w.OpenEnvelope(api, rc)
	opened := audit.OpenSlots(api, rc, w, envelope, stream, layout, c.Outputs, c.OutputCount)
	section := OpenInputs(api, c.Inputs, c.InputCount)
	section.AssertRingNotes(api, c.RingProgramID, shape.entry)
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	// The delegate signs for every owner, a published run would name a victim.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: r.delegate, V: c.SignerCount})
	owner, hidden := r.private(api, section, signers)
	signers.AssertOwners(api, section, api.Sub(1, r.delegate), owner)
	tracking := c.OpenTracking(api)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, tracking)
	rows.AssertInputOwners(api, InputRail{Delegate: r.delegate, Hidden: hidden, HiddenOwner: owner}, section.Slots)
	AssertOutputOwners(api, tracking, opened.Slots, c.OutputEntries)
	c.bindTransaction(api, gadget.NonZeroHashChain(api, section.Hashes), opened.Slots)
	c.assertBypass(api, r.delegate)
	// A ring with an own policy registry reads its root on every rail but the delegate's, no prover bit clears the thresholds.
	g := policy.Rail{ThresholdsActive: ringgadget.IsNonZero(api, c.OwnRoot), Delegate: r.delegate}.Gates(api, c.PolicyHash)
	screening := c.Screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: section.Slots, Tracking: tracking}, opened.Slots)
	api.AssertIsEqual(c.ApprovalMask, screening.ApprovalMask)
	sealed := w.SealStream(api, rc, stream, opened, audit.SpentInputs{Slots: section.Slots, Count: section.Count, Entries: c.Entries})
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, sealed, opened, signers, r)))
}

// assertBypass holds the authority rail's statement off every policy registry, a curator's update then cannot fail a delegate's proof.
func (c *Sections) assertBypass(api frontend.API, delegate frontend.Variable) {
	for _, value := range []frontend.Variable{c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.PrivateRoot} {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: delegate, V: value})
	}
}

// statement mirrors TransferStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *Sections) statement(e audit.Envelope, w audit.AuditWires, s audit.Stream, opened audit.Opened, signers SignerSet, r rail) []frontend.Variable {
	fields := slices.Concat(e.Head(w, s, shared.TransferStatementDomain), r.bits[:], []frontend.Variable{
		c.ApprovalMask, s.NoSpend,
		c.OutputCount, opened.OutputChain, s.RecordChain, s.TailChain,
		c.InputCount, c.PrivateTxHash,
	}, r.cells, []frontend.Variable{
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.TrackingRoot, c.PrivateRoot,
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
