// The program cuts every ciphertext from the layout flags, a flag off the key shifts every frame length.
//
// Read after audit/audit.go, before audit/record.go.

package audit

import (
	"github.com/consensys/gnark/frontend"
)

// Flags of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const (
	LayoutHasData = 1 << iota
	LayoutEntry
)

const layoutBits = 2

type StreamShape struct {
	InputClass, Outputs int
	Entry               bool
	Data                bool
}

type Layout struct {
	HasData, Entry frontend.Variable
}

// DecodeLayout pins the entry flag to the key and has_data to zero off a data key.
func (s StreamShape) DecodeLayout(api frontend.API, layout frontend.Variable) Layout {
	// The decomposition bounds the layout to its flags.
	bits := api.ToBinary(layout, layoutBits)
	entry := 0
	if s.Entry {
		entry = 1
	}
	api.AssertIsEqual(bits[1], entry)
	if !s.Data {
		api.AssertIsEqual(bits[0], 0)
	}
	return Layout{HasData: bits[0], Entry: bits[1]}
}
