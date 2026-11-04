package transfer

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// AnonymousShape sizes a key, Entry a spend of default-ring notes, Data one tail per slot.
type AnonymousShape struct {
	InputClass, Outputs, Withdrawals, Owners int
	Entry, Data                              bool
}

// AnonymousBases and EntryBases mirror ANONYMOUS_TRANSFER_SHAPES and ENTRY_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs, each takes every owner and data capacity.
var (
	AnonymousBases = [...]AnonymousShape{
		{InputClass: 24, Outputs: 2, Withdrawals: 4},
		{InputClass: 24, Outputs: 2, Withdrawals: 32},
		{InputClass: 16, Outputs: 4, Withdrawals: 4},
		{InputClass: 16, Outputs: 4, Withdrawals: 32},
		{InputClass: 5, Outputs: 8, Withdrawals: 24},
	}
	EntryBases = [...]AnonymousShape{
		{InputClass: 8, Outputs: 2, Withdrawals: 4, Entry: true},
		{InputClass: 8, Outputs: 4, Withdrawals: 4, Entry: true},
		{InputClass: 2, Outputs: 8, Withdrawals: 4, Entry: true},
	}
	AnonymousShapes = anonymousKeys(AnonymousBases[:])
	EntryShapes     = anonymousKeys(EntryBases[:])
)

func anonymousKeys(bases []AnonymousShape) []AnonymousShape {
	var keys []AnonymousShape
	for _, base := range bases {
		for _, owners := range ownerCapacities(base.InputClass) {
			for _, data := range []bool{false, true} {
				base.Owners, base.Data = owners, data
				keys = append(keys, base)
			}
		}
	}
	return keys
}

func (s AnonymousShape) String() string {
	family := "anonymous"
	if s.Entry {
		family = "anonymous_entry"
	}
	return fmt.Sprintf("custom_ring_transfer_%s_%d_in%d_w%d_s%d%s", family, s.Outputs, s.InputClass, s.Withdrawals, s.Owners, keySuffix(s.Data))
}

func (s AnonymousShape) sectionsShape() SectionsShape {
	return SectionsShape{inputs: s.InputClass, outputs: s.Outputs, withdrawals: s.Withdrawals, owners: s.Owners, entry: s.Entry, data: s.Data}
}

type AnonymousTransferCircuit struct {
	Shape AnonymousShape `gnark:"-"`
	// PublicOwners names the rail where every live owner is a published signer, Delegate the authority rail, neither the hidden sender rail.
	PublicOwners, Delegate frontend.Variable
	// PartyIdentities are payer, five co-signers and exit destination, an absent party is zero.
	PartyIdentities [shared.AnonymousParties]frontend.Variable
	Sections
}

func NewAnonymousTransferCircuit(shape AnonymousShape) (*AnonymousTransferCircuit, error) {
	if !slices.Contains(AnonymousShapes, shape) && !slices.Contains(EntryShapes, shape) {
		return nil, fmt.Errorf("transfer: unsupported anonymous shape %+v, want one of %v or %v", shape, AnonymousShapes, EntryShapes)
	}
	wires, err := NewSections(shape.sectionsShape())
	if err != nil {
		return nil, err
	}
	return &AnonymousTransferCircuit{Shape: shape, Sections: wires}, nil
}

func (c *AnonymousTransferCircuit) Define(api frontend.API) error {
	if err := c.validate(c.Shape.sectionsShape()); err != nil {
		return err
	}
	api.AssertIsBoolean(c.PublicOwners)
	api.AssertIsBoolean(c.Delegate)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.PublicOwners, V: c.Delegate})
	c.prove(api, c.Shape.sectionsShape(), rail{
		bits:     [2]frontend.Variable{c.PublicOwners, c.Delegate},
		cells:    c.PartyIdentities[:],
		delegate: c.Delegate,
		private:  c.hiddenOwner,
	})
	return nil
}

// hiddenOwner reads input 0, the public owner and authority rails have no owner to hide.
func (c *AnonymousTransferCircuit) hiddenOwner(api frontend.API, section InputSection, signers SignerSet) (owner, hidden frontend.Variable) {
	hidden = api.Sub(1, api.Add(c.PublicOwners, c.Delegate))
	owner = api.Mul(hidden, section.Slots[0].OwnerPkHash)
	// SPP's HiddenOwnerSigners needs a live hidden owner, one in the published run would name it.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.Sub(1, section.Slots[0].Utxo)})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(signers.missing(api, owner))})
	shared.AssertAnonymousParties(api, owner, c.PartyIdentities[:])
	return owner, hidden
}
