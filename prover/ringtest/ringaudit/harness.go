package ringaudit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// DeliveredCircuit proves the delivered audit section alone, no key proves it.
type DeliveredCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	InputClass      int               `gnark:"-"`
	audit.AuditWires
	Outputs []audit.DeliveryWires
}

func NewDeliveredCircuit(inputClass, capacity int) *DeliveredCircuit {
	return &DeliveredCircuit{InputClass: inputClass, Outputs: make([]audit.DeliveryWires, capacity)}
}

func (c *DeliveredCircuit) Define(api frontend.API) error {
	statement, _ := c.section(api, rangecheck.New(api), signerEvidence(api, c.InputClass))
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

func signerEvidence(api frontend.API, inputClass int) audit.Evidence {
	entries := make([][]frontend.Variable, inputClass)
	for i := range entries {
		entries[i] = shared.Zeros(audit.InputPrefixLen)
	}
	return audit.Evidence{Entries: entries, Count: ringgadget.SelectCount(api, 0, 0, inputClass+1)}
}

func (c *DeliveredCircuit) section(api frontend.API, rc frontend.Rangechecker, evidence audit.Evidence) ([]frontend.Variable, audit.Opened) {
	envelope := c.OpenEnvelope(api, rc)
	keyEscrow := audit.DecodeLayout(api, c.Layout, audit.LayoutEscrow|audit.LayoutReserved, 0).Flag(audit.LayoutEscrow)
	opened := audit.OpenSlots(api, rc, c.AuditWires, envelope, c.Outputs)
	stream := c.SealStream(api, audit.ConfidentialRanges(c.InputClass, len(c.Outputs)), evidence, opened.ExitRecords())
	delivered := c.Deliver(api, envelope, keyEscrow, c.Outputs, opened, stream)
	return append(envelope.Head(c.AuditWires, stream, shared.AuditStatementDomain),
		opened.OutputChain, delivered.OutputCiphertextChain, delivered.RecipientKeyChain, opened.ExitsBitmap), opened
}

// SenderShape sizes a DeliveredSenderCircuit.
type SenderShape struct {
	Inputs, Outputs int
}

// DeliveredSenderCircuit adds the in-proof owner's spend to the delivered section.
type DeliveredSenderCircuit struct {
	DeliveredCircuit
	InputCount        frontend.Variable
	Sender            frontend.Variable
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	Inputs            []shared.UtxoWires
}

func NewDeliveredSenderCircuit(shape SenderShape) *DeliveredSenderCircuit {
	return &DeliveredSenderCircuit{DeliveredCircuit: *NewDeliveredCircuit(shape.Inputs, shape.Outputs), Inputs: make([]shared.UtxoWires, shape.Inputs)}
}

func (c *DeliveredSenderCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	count := ringgadget.SelectCount(api, c.InputCount, 0, len(c.Inputs)+1)
	inputHashes := audit.SpentBySender(api, c.Inputs, count.Active, 1, c.Sender)
	statement, opened := c.section(api, rc, audit.InputPrefixEvidence(api, rc, inputHashes, count))
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, inputHashes, shared.UtxoHashes(api, opened.Slots), nil, c.PrivateTxBlinding))
	statement = append(statement, c.InputCount, c.PrivateTxHash, c.Sender)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// AnonymousCircuit proves the anonymous audit section alone, no key proves it.
type AnonymousCircuit struct {
	PublicInputHash frontend.Variable         `gnark:",public"`
	Shape           audit.AnonymousAuditShape `gnark:"-"`
	audit.AuditWires
	Outputs           []audit.AnonymousOutputWires
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	SenderKey         []frontend.Variable
	InputCount        frontend.Variable
	Inputs            []shared.UtxoWires
	PartyIdentities   [3]frontend.Variable
}

func NewAnonymousCircuit(shape audit.AnonymousAuditShape) *AnonymousCircuit {
	senderKey := 0
	if shape.FullOpenings {
		senderKey = 32
	}
	return &AnonymousCircuit{
		Shape:     shape,
		Outputs:   make([]audit.AnonymousOutputWires, shape.Outputs),
		SenderKey: make([]frontend.Variable, senderKey),
		Inputs:    make([]shared.UtxoWires, shape.InputClass),
	}
}

func (c *AnonymousCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	envelope := c.OpenEnvelope(api, rc)
	fixed := 0
	if c.Shape.FullOpenings {
		fixed = audit.LayoutFullOpenings
	}
	audit.DecodeLayout(api, c.Layout, audit.LayoutReserved, fixed)
	opened := audit.OpenSlots(api, rc, c.AuditWires, envelope, c.Outputs)
	spent := audit.Spend(api, rc, c.Shape, c.Inputs, c.InputCount, c.RingProgramID, c.SenderKey)
	shared.AssertAnonymousParties(api, spent.SenderPkHash, c.PartyIdentities)
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, spent.InputHashes, shared.UtxoHashes(api, opened.Slots), nil, c.PrivateTxBlinding))
	stream := c.SealStream(api, c.Shape.Ranges(), spent.Evidence, opened.AnonymousRecords(api, c.Outputs))
	statement := append(envelope.Head(c.AuditWires, stream, shared.AuditStatementDomain),
		opened.OutputChain, opened.RecordChain(api, stream), c.InputCount, opened.ExitsBitmap, c.PrivateTxHash,
		c.PartyIdentities[0], c.PartyIdentities[1], c.PartyIdentities[2])
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}
