// Package transfer proves a ring transfer's audit, policy and owner predicates in one proof.
//
// An auditor of a ring transfer starts here. SPP's proof authorizes the spend, derives the
// nullifiers, conserves each asset and range checks each amount. SPP reads no list, no cap and no
// auditor key, and a ring note's owner, asset and amount stay behind its commitment, so the ring program
// cannot evaluate a ring rule itself. The ring proof opens the commitments SPP publishes and spends, and proves the ring's
// predicates over those openings. The program verifies it, then calls SPP on the same frame, in
// programs/custom-ring/src/instructions/transfer/processor.rs.
//
// Read after zolana/prover/server/circuits/spp_transaction/shared/transaction.go, the statement
// the ring extends. Read before, in the order Define calls them, shared/utxo.go, audit/audit.go,
// transfer/input.go, policy/record_pool.go, policy/tracking.go, transfer/owners.go,
// audit/signer_data.go, policy/policy.go. Then prover/ring/ring.go, outside Define.
//
// Two values tie the proofs together. Both proofs reopen private_tx_hash, so the notes read here are
// the notes SPP moves. The program hashes output_chain from the frame it forwards, so every
// published slot, a dummy's included, is one the ring proof opened.
//
// One circuit serves every rail, and the statement's bits select the rail.
//   - All bits clear is the signer rail. Every input owner signs as a Solana account in the run.
//   - InProof names Sender in the statement, that owner signs inside SPP's circuit.
//   - Hidden keeps input 0's owner out of the statement, that owner signs inside SPP's circuit.
//   - Delegate is the ring's permanent delegate. It signs for every owner, the run stays empty and
//     no policy section binds.
//
// The hardest arguments live at the code they govern.
//   - Outflow, charge, peak and the telescoping floor are in policy/outflow.go.
//   - The bound behind every amount comparison is in policy/comparator.go.
//   - The record pool, absence proofs and deduplication are in policy/record_pool.go.
//   - Salted reads and the tracking floor are in policy/subjects.go.
//   - Input asset subjects are in policy/subjects.go and policy/rules.go.
//   - Owner rows and the zero key rule are in transfer/owners.go.
//   - Approval totals are in policy/screen.go, signer data counts in audit/signer_data.go.
//
// Properties, the statement proves the following on the rail its bits select.
//  1. Every published output and spent input opens to the commitment SPP publishes or spends, through
//     the output chain and private_tx_hash, the same wires serve every section below.
//  2. The auditor stream seals each live output's opening, each default-ring input's opening and the
//     count of spent notes under the ring's auditor key, per package audit. A ring input opens through
//     the record that created it.
//  3. Every live input is a note of the bound ring, or of the default ring on an entry key. Its owner
//     is in the published signer run, the hidden owner or the in-proof sender, the delegate rail excepted.
//  4. A hidden owner is live, stays out of the run and differs from every public party.
//  5. A live ring slot's nonzero key is its owner's row key under the tracking root, a zero key on an
//     output leaves its owner absent.
//  6. Each entry of the signer run counts its data-bearing outputs, per audit.SignerDataCounts.
//  7. The policy's rules, limits and approval bits hold under the bound roots, off the delegate rail.
//
// The statement relies on the program for what no circuit can see. The program hashes the run from
// the signed owner accounts, reads each root live at the frame's revision, refuses a tracking root
// below a salted source's floor, folds the gross from the settled legs and reads the legs from their
// accounts.
//
// It proves nothing about a recipient's body or tag, SPP's external data hash binds those bytes alone.
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
	// SignerDataCounts is the statement's packed count per run entry, zero unless a run entry owns a data-bearing output.
	SignerDataCounts frontend.Variable
	// Rows hold every live input owner, a delegate's zero key note aside, ascending with zero rows last off the authority rail. They stay private, the constraints alone hold them. A row with no input holds nothing and only adds its own sender rules.
	Rows []frontend.Variable
	policy.Tracking
	// ApprovalMask is the proven approval bits, the program demands their co-signers.
	ApprovalMask frontend.Variable
	// ApprovalTotals is zero unless the frame discloses the totals to a co-signer.
	ApprovalTotals frontend.Variable
	// ApprovalBlinder enters no statement. The wallet draws it fresh per transaction, no constraint holds its freshness.
	ApprovalBlinder frontend.Variable
	policy.Policy
}

// transactionBinding is SPP's private transaction hash and its blinding, the proof reopens the hash over the slots the audit opened.
type transactionBinding struct {
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	// AddressChain is SPP's chain of address slot nullifiers, zero without one, SPP alone reads the slots.
	AddressChain frontend.Variable
}

func NewSections(shape Shape) (Sections, error) {
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.Owners, SaltedKeys: shape.saltedKeys(), Spent: shape.Inputs}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
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
	// 1. One rail, every later predicate reads its bits.
	c.assertRail(api)
	rc := rangecheck.New(api)
	// 2. The output slots open and the sealed key derives each published blinding. Every later section reads these wires, so what it proves is about the notes step 7 ties to SPP.
	w := audit.AuditWires{FirstNullifier: c.FirstNullifier, RingProgramID: c.RingProgramID, TxViewingSk: c.TxViewingSk, AuditorPk: c.AuditorPk, Salt: c.Salt, Layout: c.Layout}
	stream := c.Shape.Stream()
	layout := stream.DecodeLayout(api, c.Layout)
	envelope := w.OpenEnvelope(api, rc)
	opened := audit.OpenSlots(api, rc, w, envelope, stream, layout, c.Outputs, c.OutputCount)
	// 3. The inputs open with dummies last, a live input belongs to the bound ring or on an entry key to the default ring.
	section := OpenInputs(api, c.Inputs, c.InputCount)
	section.AssertRingNotes(api, c.RingProgramID, c.Shape.Entry)
	// 4. The signer run opens under the chain the program rebuilds, and off the delegate rail every live input's owner is in it, hidden or the in-proof sender.
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	// The delegate signs for every owner, a published run would name a victim.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.SignerCount})
	hiddenOwner := c.hiddenOwner(api, section, signers)
	// At most one term is nonzero, assertRail excludes the bits and zeroes Sender off InProof.
	signers.AssertOwners(api, section, api.Sub(1, c.Delegate), api.Add(hiddenOwner, c.Sender))
	// 5. Owner rows and output keys read the tracking root. The auditor derives a nullifier from the secret sealed behind an enrolled key or from the public zero secret, so after the step no ring note carries a key the auditor cannot read.
	tracking := c.OpenTracking(api)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, tracking)
	rows.AssertInputOwners(api, InputRail{Delegate: c.Delegate, Hidden: c.Hidden, HiddenOwner: hiddenOwner}, section.Slots)
	AssertOutputOwners(api, tracking, opened.Slots, c.OutputEntries)
	// 6. Each run entry's data-bearing outputs are counted from the opened slots, a signer's check needs the run from step 4 and the slots from step 2.
	audit.SignerDataCounts{Packed: c.SignerDataCounts, Members: signers.Members, Active: signers.Count.Active, Slots: opened.Slots}.Assert(api)
	// 7. private_tx_hash reopens over these slots, an opening other than SPP's fails here, and a delegate's statement stays off every policy registry.
	c.bindTransaction(api, gadget.NonZeroHashChain(api, section.Hashes), opened.Slots)
	c.assertBypass(api, c.Delegate)
	// 8. The policy screens the bound slots. The rows hold every live input owner by step 5, so no owner's funds escape the sender rules or the attribution.
	// A ring with an own policy registry reads its root on every rail but the delegate's, no prover bit clears the thresholds.
	g := policy.Rail{ThresholdsActive: ringgadget.IsNonZero(api, c.OwnRoot), Delegate: c.Delegate}.Gates(api, c.PolicyHash)
	screening := c.Screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: section.Slots, Tracking: tracking}, opened.Slots)
	// The mask is equal and never at least. A short mask would drop a demanded co-signer, the program acts on these bits and derives no threshold.
	api.AssertIsEqual(c.ApprovalMask, screening.ApprovalMask)
	screening.AssertApprovalTotals(api, c.ApprovalTotals, c.ApprovalBlinder)
	// 9. The stream seals the outputs, the entry evidence and the spent count, the statement binds its digest, chains and every public value.
	sealed := w.SealStream(api, rc, envelope, stream, opened, audit.SpentInputs{Slots: section.Slots, Count: section.Count, Entries: c.Entries})
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

// bindTransaction holds PrivateTxHash to Poseidon(input chain, output chain, address chain, blinding), a note called an address would leave the input chain SPP hashed.
func (b transactionBinding) bindTransaction(api frontend.API, inputChain frontend.Variable, outputs []shared.Output) {
	outputChain := gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs))
	api.AssertIsEqual(b.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, b.AddressChain, b.PrivateTxBlinding}))
}

// assertBypass holds the authority rail's statement off every policy registry, a curator's update then cannot fail a delegate's proof.
func (c *Sections) assertBypass(api frontend.API, delegate frontend.Variable) {
	for _, value := range []frontend.Variable{c.PolicyHash, c.OwnRoot, c.CuratorRoot} {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: delegate, V: value})
	}
}

// statement mirrors TransferStatement::elements in program-libs/interface/src/proof/statement.rs.
// The program rebuilds every element from the frame and live accounts, a wire outside the list stays private and only a constraint fixes it.
func (c *TransferCircuit) statement(e audit.Envelope, w audit.AuditWires, s audit.Stream, opened audit.Opened, signers SignerSet) []frontend.Variable {
	fields := slices.Concat(e.Head(w, s, shared.TransferStatementDomain), []frontend.Variable{
		c.InProof, c.Hidden, c.Delegate, c.ApprovalMask, c.ApprovalTotals, c.SignerDataCounts, s.NoSpend,
		c.OutputCount, opened.OutputChain, s.RecordChain, s.TailChain,
		c.InputCount, c.PrivateTxHash, c.Sender,
	}, c.PartyIdentities[:], []frontend.Variable{
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot, c.TrackingRoot,
	}, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]), []frontend.Variable{c.WithdrawalHash})
	return closeStatement(fields)
}

// closeStatement ends on the element count, itself included, HashChain4 pads zeros and a nonzero last element hashes another length apart.
func closeStatement(fields []frontend.Variable) []frontend.Variable {
	return append(fields, len(fields)+1)
}

func publicSlots(assets, amounts, gross []frontend.Variable) []frontend.Variable {
	fields := make([]frontend.Variable, 0, 3*len(assets))
	for k := range assets {
		fields = append(fields, assets[k], amounts[k], gross[k])
	}
	return fields
}
