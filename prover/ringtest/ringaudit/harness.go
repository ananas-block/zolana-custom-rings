package ringaudit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// DeliveredCircuit proves the delivered audit section alone, no key proves it.
type DeliveredCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	audit.AuditWires
	Outputs []audit.DeliveryWires
}

func NewDeliveredCircuit(capacity int) *DeliveredCircuit {
	return &DeliveredCircuit{Outputs: make([]audit.DeliveryWires, capacity)}
}

func (c *DeliveredCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	envelope := c.Seal(api, rc)
	layout := audit.DecodeLayout(api, c.Layout, audit.LayoutExits|audit.LayoutEscrow|audit.LayoutReserved, 0)
	delivered := c.Deliver(api, rc, envelope, layout, c.Outputs)
	statement := append(envelope.Head(c.AuditWires, shared.AuditStatementDomain),
		delivered.OutputChain, delivered.BodyChain, delivered.Disclosure(api, envelope, layout), delivered.RecipientKeyChain)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// SenderShape sizes a DeliveredSenderCircuit.
type SenderShape struct {
	Inputs, Outputs int
}

// DeliveredSenderCircuit adds the in-proof owner's spend to the delivered section.
type DeliveredSenderCircuit struct {
	DeliveredCircuit
	Sender            frontend.Variable
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
	Inputs            []shared.UtxoWires
}

func NewDeliveredSenderCircuit(shape SenderShape) *DeliveredSenderCircuit {
	return &DeliveredSenderCircuit{DeliveredCircuit: *NewDeliveredCircuit(shape.Outputs), Inputs: make([]shared.UtxoWires, shape.Inputs)}
}

func (c *DeliveredSenderCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	envelope := c.Seal(api, rc)
	layout := audit.DecodeLayout(api, c.Layout, audit.LayoutExits|audit.LayoutEscrow|audit.LayoutReserved, 0)
	delivered := c.Deliver(api, rc, envelope, layout, c.Outputs)
	inputHashes := audit.SpentBySender(api, c.Inputs, 1, 1, c.Sender)
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, inputHashes, shared.UtxoHashes(api, delivered.Slots), nil, c.PrivateTxBlinding))
	statement := append(envelope.Head(c.AuditWires, shared.AuditStatementDomain),
		delivered.OutputChain, delivered.BodyChain, delivered.Disclosure(api, envelope, layout), delivered.RecipientKeyChain, c.PrivateTxHash, c.Sender)
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
	envelope := c.Seal(api, rc)
	fixed := 0
	if c.Shape.FullOpenings {
		fixed = audit.LayoutFullOpenings
	}
	layout := audit.DecodeLayout(api, c.Layout, audit.LayoutExits|audit.LayoutReserved, fixed)
	anonymous := c.Anonymous(api, rc, envelope, layout, c.Shape, c.Outputs, c.Inputs, c.InputCount, c.SenderKey)
	shared.AssertAnonymousParties(api, anonymous.SenderPkHash, c.PartyIdentities)
	api.AssertIsEqual(c.PrivateTxHash, transaction.PrivateTxHashCircuit(api, anonymous.InputHashes, shared.UtxoHashes(api, anonymous.Slots), nil, c.PrivateTxBlinding))
	statement := append(envelope.Head(c.AuditWires, shared.AuditStatementDomain),
		anonymous.OutputChain, anonymous.Disclosure(api, envelope, layout), c.PrivateTxHash,
		c.PartyIdentities[0], c.PartyIdentities[1], c.PartyIdentities[2])
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}
