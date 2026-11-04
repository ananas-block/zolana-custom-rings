package transfer

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// ConfidentialShape sizes a key, Inputs the slots every rail opens and the signers it can bind, Owners the rows, Entry a spend of default-ring notes, Data one tail per slot.
type ConfidentialShape struct {
	Inputs, Outputs, Withdrawals, Owners int
	Entry, Data                          bool
}

// ConfidentialBases mirrors CONFIDENTIAL_TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs, each takes every owner and data capacity.
var ConfidentialBases = [...]ConfidentialShape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4},
	{Inputs: 24, Outputs: 2, Withdrawals: 32},
	{Inputs: 24, Outputs: 4, Withdrawals: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 32},
	{Inputs: 16, Outputs: 8, Withdrawals: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 32},
	{Inputs: 5, Outputs: 16, Withdrawals: 8},
}

var (
	ConfidentialShapes = confidentialKeys(ConfidentialBases[:], false)
	// ConfidentialEntryShapes spend a default-ring note on the signer rails.
	ConfidentialEntryShapes = confidentialKeys(entryBases(), true)
)

func confidentialKeys(bases []ConfidentialShape, entry bool) []ConfidentialShape {
	var keys []ConfidentialShape
	for _, base := range bases {
		for _, owners := range ownerCapacities(base.Inputs) {
			for _, data := range []bool{false, true} {
				base.Owners, base.Entry, base.Data = owners, entry, data
				keys = append(keys, base)
			}
		}
	}
	return keys
}

func entryBases() []ConfidentialShape {
	bases := make([]ConfidentialShape, len(EntryBases))
	for i, base := range EntryBases {
		bases[i] = ConfidentialShape{Inputs: base.InputClass, Outputs: base.Outputs, Withdrawals: base.Withdrawals}
	}
	return bases
}

func (s ConfidentialShape) String() string {
	family := "confidential"
	if s.Entry {
		family = "confidential_entry"
	}
	return fmt.Sprintf("custom_ring_transfer_%s_%d_in%d_w%d_s%d%s", family, s.Outputs, s.Inputs, s.Withdrawals, s.Owners, keySuffix(s.Data))
}

func keySuffix(data bool) string {
	if data {
		return "_data"
	}
	return ""
}

func (s ConfidentialShape) sectionsShape() SectionsShape {
	return SectionsShape{inputs: s.Inputs, outputs: s.Outputs, withdrawals: s.Withdrawals, owners: s.Owners, entry: s.Entry, data: s.Data}
}

type ConfidentialTransferCircuit struct {
	Shape ConfidentialShape `gnark:"-"`
	// InProof and Delegate name the rail, the signer rail carries neither.
	InProof, Delegate frontend.Variable
	// Sender is the in-proof owner, zero on the signer and authority rails.
	Sender frontend.Variable
	Sections
}

func NewConfidentialTransferCircuit(shape ConfidentialShape) (*ConfidentialTransferCircuit, error) {
	if !slices.Contains(ConfidentialShapes, shape) && !slices.Contains(ConfidentialEntryShapes, shape) {
		return nil, fmt.Errorf("transfer: unsupported confidential shape %+v, want one of %v or %v", shape, ConfidentialShapes, ConfidentialEntryShapes)
	}
	wires, err := NewSections(shape.sectionsShape())
	if err != nil {
		return nil, err
	}
	return &ConfidentialTransferCircuit{Shape: shape, Sections: wires}, nil
}

func (c *ConfidentialTransferCircuit) Define(api frontend.API) error {
	if err := c.validate(c.Shape.sectionsShape()); err != nil {
		return err
	}
	c.assertRail(api)
	c.prove(api, c.Shape.sectionsShape(), rail{
		bits:     [2]frontend.Variable{c.InProof, c.Delegate},
		cells:    []frontend.Variable{c.Sender},
		delegate: c.Delegate,
		private: func(frontend.API, InputSection, SignerSet) (owner, hidden frontend.Variable) {
			return c.Sender, 0
		},
	})
	return nil
}

// assertRail holds the bits to one rail, only the in-proof rail names a public sender.
func (c *ConfidentialTransferCircuit) assertRail(api frontend.API) {
	api.AssertIsBoolean(c.InProof)
	api.AssertIsBoolean(c.Delegate)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: c.Delegate, V: c.InProof})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, c.InProof), V: c.Sender})
}
