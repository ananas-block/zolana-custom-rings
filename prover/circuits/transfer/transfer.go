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
// transfer/input.go, policy/record_pool.go, policy/credentials.go, transfer/owners.go,
// audit/signer_data.go, policy/policy.go. Then prover/ring/ring.go, outside Define.
//
// Both proofs reopen private_tx_hash over the note, output and address chains and the transaction blinding.
// The program also binds output_chain and input_nullifier_chain from the exact frame it forwards to SPP.
// The output chain covers published dummies. The nullifier chain fixes absolute address positions through
// the selected address subsequence, SPP's distinct nullifiers and the dummy suffix enforced by both proofs.
//
// One circuit serves every rail, and the statement's bits select the rail.
//   - All bits clear is the signer rail. Every note owner signs as a Solana account in the run.
//   - InProof names Sender in the statement, that owner signs inside SPP's circuit.
//   - Hidden keeps input 0's owner out of the statement, that owner signs inside SPP's circuit.
//   - Delegate is the ring's permanent delegate. It signs for every owner, the run stays empty and
//     no policy section binds.
//
// The hardest arguments live at the code they govern.
//   - Outflow, charge, peak and the telescoping floor are in policy/outflow.go.
//   - The bound behind every amount comparison is in policy/comparator.go.
//   - The record pool, absence proofs and deduplication are in policy/record_pool.go.
//   - Salted reads and the absence floor are in policy/subjects.go.
//   - Input asset subjects are in policy/subjects.go and policy/rules.go.
//   - Owner rows and the zero key rule are in transfer/owners.go.
//   - Approval totals are in policy/screen.go, signer data counts in audit/signer_data.go.
//
// Properties, the statement proves the following on the rail its bits select.
//  1. Every published output and spent note opens to the commitment SPP publishes or spends, through
//     the output chain and private_tx_hash, the same wires serve every section below.
//  2. The auditor stream seals each live output opening, each default-ring note opening, the note count
//     and the address bitmap under the auditor key. A ring note opens through the record that created it.
//  3. Every input note belongs to the bound ring, or to the default ring on an entry key. Its owner
//     is in the published signer run, the hidden owner or the in-proof sender, the delegate rail excepted.
//  4. A hidden owner owns the note at input zero, stays out of the run and differs from every public party.
//  5. A ring note key outside ZeroNullifierPk equals its owner's permanent credential key. Zero-key outputs need no
//     credential for the key check, applicable salted rules still require an authenticated owner opening.
//  6. Each entry of the signer run counts its data-bearing outputs, per audit.SignerDataCounts.
//  7. The policy's rules, limits and approval bits hold under the bound roots, off the delegate rail.
//  8. InputCount and the exact capacity of ordered nullifiers enter input_nullifier_chain, with a zero tail.
//     Notes and addresses may interleave before the dummy suffix. SPP alone authorizes address creation.
//
// The statement relies on the program for what no circuit can see. The program hashes the run from
// the signed owner accounts, authenticates the credential PDA owner and reads accepted SPP state roots.
// It refuses an address root below any salted source's absence floor, folds the settled gross and reads legs from their accounts.
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
	InputNullifiers []frontend.Variable
	// Entries open default-ring inputs to the auditor, none off an entry key.
	Entries []audit.EntryWires
	transactionBinding
	SignerCount frontend.Variable
	// Signers is the program's owner signer run, zero past SignerCount.
	Signers []frontend.Variable
	// SignerDataCounts is the statement's packed count per run entry, zero unless a run entry owns a data-bearing output.
	SignerDataCounts frontend.Variable
	// Rows hold every input note owner, a delegate's zero key note aside, ascending with zero rows last off the authority rail. They stay private, the constraints alone hold them. A row with no input holds nothing and only adds its own sender rules.
	Rows []frontend.Variable
	policy.Credentials
	// ApprovalMask is the proven approval bits, the program demands their co-signers.
	ApprovalMask frontend.Variable
	// ApprovalTotals is zero unless the frame discloses the totals to a co-signer.
	ApprovalTotals frontend.Variable
	// ApprovalBlinder enters no statement. The wallet draws it fresh per transaction, no constraint holds its freshness.
	ApprovalBlinder frontend.Variable
	policy.Policy
}

// transactionBinding binds the audited slots to SPP through the private transaction hash and the published nullifier digest.
type transactionBinding struct {
	PrivateTxHash       frontend.Variable
	PrivateTxBlinding   frontend.Variable
	InputNullifierChain frontend.Variable
}

func NewSections(shape Shape) (Sections, error) {
	if err := shared.ValidateInputCapacity(shape.Inputs); err != nil {
		return Sections{}, err
	}
	p, err := policy.NewPolicy(policy.InputsShape{Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Senders: shape.Owners, SaltedKeys: shape.saltedKeys(), Spent: shape.Inputs}.Inputs(), policy.RecordPoolShape{}, transaction.NPublicSlots)
	if err != nil {
		return Sections{}, err
	}
	credentials, err := policy.NewCredentials(shape.Owners, shape.Outputs, shape.trackedWithdrawals())
	if err != nil {
		return Sections{}, err
	}
	return Sections{
		Outputs:         make([]audit.OutputWires, shape.Outputs),
		Inputs:          make([]shared.UtxoWires, shape.Inputs),
		InputNullifiers: make([]frontend.Variable, shape.Inputs),
		Entries:         make([]audit.EntryWires, shape.entries()),
		Signers:         make([]frontend.Variable, shape.Inputs),
		Rows:            make([]frontend.Variable, shape.Owners),
		Credentials:     credentials,
		Policy:          p,
	}, nil
}

func (c *Sections) validate(shape Shape) error {
	if err := shared.ValidateInputCapacity(shape.Inputs); err != nil {
		return err
	}
	return errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), shape.Inputs),
		shared.ValidateLength("transfer", "input nullifier", len(c.InputNullifiers), shape.Inputs),
		shared.ValidateLength("transfer", "entry", len(c.Entries), shape.entries()),
		shared.ValidateLength("transfer", "signer", len(c.Signers), shape.Inputs),
		shared.ValidateLength("transfer", "owner row", len(c.Rows), shape.Owners),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), shape.Withdrawals),
		c.ValidateCredentials(shape.Owners, shape.Outputs, shape.trackedWithdrawals()),
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
	hasData := stream.DecodeLayout(api, c.Layout)
	envelope := w.OpenEnvelope(api, rc)
	opened := audit.OpenSlots(api, rc, w, envelope, hasData, c.Outputs, c.OutputCount)
	// 3. The input classes and private nullifiers bind to the exact published order. FirstNullifier ties
	// the audit derivation to the same list, and only notes incur the ring membership check.
	section := OpenInputs(api, c.Inputs, c.InputCount, c.InputNullifiers)
	api.AssertIsEqual(c.InputNullifierChain, section.NullifierChain)
	api.AssertIsEqual(c.FirstNullifier, c.InputNullifiers[0])
	section.AssertRingNotes(api, c.RingProgramID, c.Shape.Entry)
	// 4. The signer run binds the note owners to the selected rail, with the hidden and in-proof owner exceptions.
	// SPP alone checks address owners, address-only inputs still require its authorization.
	signers := OpenSigners(api, c.Signers, c.SignerCount)
	// The delegate signs for every owner, a published run would name a victim.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.SignerCount})
	hiddenOwner := c.hiddenOwner(api, section, signers)
	// At most one term is nonzero, assertRail excludes the bits and zeroes Sender off InProof.
	signers.AssertOwners(api, section, api.Sub(1, c.Delegate), api.Add(hiddenOwner, c.Sender))
	// 5. Every sender row authenticates its credential result, and every output key outside ZeroNullifierPk needs a matching credential.
	// A zero-key output stays auditable without an opening here, the policy still enforces any salted payee read.
	credentials := c.OpenCredentials(api, c.RingProgramID)
	rows := OpenOwnerRows(api, c.Rows, c.RowEntries, credentials)
	rows.AssertInputOwners(api, InputRail{Delegate: c.Delegate, Hidden: c.Hidden, HiddenOwner: hiddenOwner}, section.Slots)
	AssertOutputOwners(api, credentials, opened.Slots, c.OutputEntries)
	// 6. Each run entry's data-bearing outputs are counted from the opened slots, a signer's check needs the run from step 4 and the slots from step 2.
	audit.SignerDataCounts{Packed: c.SignerDataCounts, Members: signers.Members, Active: signers.Count.Active, Slots: opened.Slots}.Assert(api)
	// 7. PrivateTxHash binds the opened notes and derived address subsequence to SPP. Together with
	// step 3 and the dummy suffix, the chains fix the input classes at their absolute published positions.
	c.bindTransaction(api, section, opened.Slots)
	c.assertBypass(api, c.Delegate)
	// 8. The policy screens the bound slots. The rows hold every input note owner by step 5, so no owner's funds escape the sender rules or the attribution.
	// A ring with an own policy registry reads its root on every rail but the delegate's, no prover bit clears the thresholds.
	g := policy.Rail{ThresholdsActive: ringgadget.IsNonZero(api, c.OwnRoot), Delegate: c.Delegate}.Gates(api, c.PolicyHash)
	screening := c.Screen(api, rc, g, policy.Spend{Senders: rows.Members, Inputs: section.Slots, Credentials: credentials}, opened.Slots)
	// The mask is equal and never at least. A short mask would drop a demanded co-signer, the program acts on these bits and derives no threshold.
	api.AssertIsEqual(c.ApprovalMask, screening.ApprovalMask)
	screening.AssertApprovalTotals(api, c.ApprovalTotals, c.ApprovalBlinder)
	// 9. The audit reads the same selectors that formed the transaction chains. Its note count and address
	// bitmap distinguish spends, address creation and padding. NoSpend is set exactly when no note is spent.
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

// bindTransaction follows SPP's Poseidon order of note chain, output chain, address chain and blinding.
// AddressChain derives from the statement-bound nullifiers. SPP's uniqueness and the shared dummy suffix
// bind the merged note and address order even though each NonZeroHashChain removes unselected slots.
func (b transactionBinding) bindTransaction(api frontend.API, inputs InputSection, outputs []shared.Output) {
	inputChain := gadget.NonZeroHashChain(api, inputs.Hashes)
	outputChain := gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs))
	api.AssertIsEqual(b.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, inputs.AddressChain, b.PrivateTxBlinding}))
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
		c.InputCount, c.InputNullifierChain, c.PrivateTxHash, c.Sender,
	}, c.PartyIdentities[:], []frontend.Variable{
		c.SignerCount, signers.Chain,
		c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, c.Credentials.StatementFields(), publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]), []frontend.Variable{c.WithdrawalHash})
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
