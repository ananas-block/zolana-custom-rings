// Proves a transfer on the anonymous rail, the policy screens the hidden owner
// the audit names.
//
// Read after transfer/confidential.go. Read before prover/ring/ring.go.

package transfer

import (
	"errors"
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

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
	Exempt           frontend.Variable
	ApprovalRequired frontend.Variable
	Outputs          []audit.AnonymousOutputWires
	// SenderKey is the hidden owner's Ed25519 key on an entry key, a commitment key carries none.
	SenderKey []frontend.Variable
	// InputCount equals the published nullifier count on an entry key and lies within one of it on a commitment key.
	InputCount frontend.Variable
	Inputs     []shared.UtxoWires
	transactionBinding
	// PartyIdentities are payer, configured co-signer and withdrawal owner, an absent party is zero.
	PartyIdentities [3]frontend.Variable
	policy.Policy
}

func NewAnonymousTransferCircuit(shape AnonymousShape) (*AnonymousTransferCircuit, error) {
	keyed := shape.keyed()
	if !slices.Contains(AnonymousShapes[:], keyed) && !slices.Contains(EntryShapes[:], keyed) {
		return nil, fmt.Errorf("transfer: unsupported anonymous shape %+v, want one of %v or %v", keyed, AnonymousShapes, EntryShapes)
	}
	p, err := policy.NewPolicy(policy.NewPolicyInputs(shape.Outputs, shape.Withdrawals, false), shape.Records, transaction.NPublicSlots)
	if err != nil {
		return nil, err
	}
	senderKey := 0
	if shape.FullOpenings {
		senderKey = 32
	}
	return &AnonymousTransferCircuit{
		Shape:     shape,
		Outputs:   make([]audit.AnonymousOutputWires, shape.Outputs),
		SenderKey: make([]frontend.Variable, senderKey),
		Inputs:    make([]shared.UtxoWires, shape.InputClass),
		Policy:    p,
	}, nil
}

func (c *AnonymousTransferCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.Validate(transaction.NPublicSlots),
		shared.ValidateLength("transfer", "output", len(c.Outputs), c.Shape.Outputs),
		shared.ValidateLength("transfer", "input", len(c.Inputs), c.Shape.InputClass),
		shared.ValidateLength("transfer", "escrow hash", len(c.CtHashes), c.Shape.Outputs),
		shared.ValidateLength("transfer", "withdrawal", len(c.Withdrawals), c.Shape.Withdrawals),
	); err != nil {
		return err
	}
	rc := rangecheck.New(api)
	w := c.auditWires(c.RingProgramID)
	api.AssertIsBoolean(c.Exempt)
	// 1. The envelope seals tx_viewing_sk to the auditor and the layout flags fix the published fields, an anonymous ring escrows no key.
	envelope := w.Seal(api, rc)
	fixed := 0
	if c.Shape.FullOpenings {
		fixed = audit.LayoutFullOpenings
	}
	layout := audit.DecodeLayout(api, c.Layout, audit.LayoutExits|audit.LayoutReserved, fixed)
	// 2. Every output slot opens to the auditor, every spent UTXO is the sender's, and every party differs from the sender.
	anonymous := w.Anonymous(api, rc, envelope, layout, c.Shape.audit(), c.Outputs, c.Inputs, c.InputCount, c.SenderKey)
	shared.AssertAnonymousParties(api, anonymous.SenderPkHash, c.PartyIdentities)
	// 3. SPP's private transaction hash reopens over the slots the audit opened with no address input.
	c.bindTransaction(api, gadget.NonZeroHashChain(api, anonymous.InputHashes), anonymous.Slots)
	// 4. The policy screens the same slots under the sender the inputs prove, no recipient is published and no key escrowed.
	approval := c.Screen(api, rc, policy.Rail{Exempt: c.Exempt, KeyEscrow: 0, Delegate: 0, Published: 0}, anonymous.SenderPkHash, anonymous.Slots)
	// 5. approval_required is the outflow's verdict.
	api.AssertIsEqual(c.ApprovalRequired, approval)
	// 6. The one public input commits the statement the program rebuilds.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(envelope, w, anonymous, anonymous.Disclosure(api, envelope, layout))))
	return nil
}

// statement is the anonymous transfer preimage, mirrored by TransferStatement::elements under TransferFamily::Anonymous in program-libs/interface/src/proof/statement.rs.
//
//	head ‖ exempt, approval_required, output_chain, disclosure_chain, private_tx_hash, party0, party1, party2,
//	policy_hash, own_root, curator_root, asset, net and gross per public slot, withdrawal_hash, length, version
func (c *AnonymousTransferCircuit) statement(e audit.Envelope, w audit.AuditWires, a audit.Anonymous, disclosure frontend.Variable) []frontend.Variable {
	fields := slices.Concat(e.Head(w, shared.TransferStatementDomain), []frontend.Variable{
		c.Exempt, c.ApprovalRequired, a.OutputChain, disclosure, c.PrivateTxHash,
		c.PartyIdentities[0], c.PartyIdentities[1], c.PartyIdentities[2],
		c.PolicyHash, c.OwnRoot, c.CuratorRoot,
	}, publicSlots(c.PublicAssets[:], c.PublicAmounts[:], c.PublicGross[:]))
	return closeStatement(append(fields, c.WithdrawalHash))
}
