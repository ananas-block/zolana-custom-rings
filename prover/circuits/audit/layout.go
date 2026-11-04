// The program cuts every ciphertext from the layout flags, a flag off the key shifts every frame length.
//
// Read after audit/audit.go. Read before audit/record.go.

package audit

import (
	"github.com/consensys/gnark/frontend"
)

// Flags of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const (
	// LayoutHasData sets the statement's has_data bit, the frame transmits one tail per published slot.
	LayoutHasData = 1 << iota
	// LayoutEntry names a key with entry capacity, the envelope carries default bits and one evidence entry per published input.
	LayoutEntry
)

const layoutBits = 2

// StreamShape sizes one key's auditor stream.
type StreamShape struct {
	InputClass, Outputs int
	// Entry adds default bits and one evidence entry per input slot.
	Entry bool
	// Data adds one tail per output slot, a key without it runs no tail cipher blocks.
	Data bool
}

// Layout is the decoded layout value.
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
