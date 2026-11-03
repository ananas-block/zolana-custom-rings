// Decodes the transfer statement's layout flags. The program cuts every ciphertext
// from them and the exits bitmap, a flag off the key shifts every frame length.
//
// Read after audit/audit.go, ringgadget/count.go. Read before
// audit/delivered.go, audit/anonymous.go.

package audit

import (
	"math/bits"

	"github.com/consensys/gnark/frontend"
)

// Flags of the audit statement's layout value, mirrored by AuditLayout::value in program-libs/interface/src/proof/disclosure.rs.
const (
	// Bit 0 stays clear in every key, exits_bitmap alone records exits.
	_ = 1 << iota
	// LayoutEscrow is the config's key escrow, the policy section escrows every output nullifier key the ciphertexts leave out.
	LayoutEscrow
	// LayoutReserved is free in every key, the program sends it clear.
	LayoutReserved
	// LayoutFullOpenings is the anonymous entry layout, every spent UTXO opens in the envelope.
	LayoutFullOpenings
)

const layoutBits = 4

// Layout is the decoded layout value, every flag outside free pinned.
type Layout struct {
	flags [layoutBits]frontend.Variable
}

// DecodeLayout pins every flag outside free to its bit of fixed.
func DecodeLayout(api frontend.API, layout frontend.Variable, free, fixed int) Layout {
	if free&fixed != 0 {
		panic("audit: a layout flag is both free and fixed")
	}
	// The decomposition bounds the layout to its flags.
	l := Layout{flags: [layoutBits]frontend.Variable(api.ToBinary(layout, layoutBits))}
	for i, flag := range l.flags {
		if free&(1<<i) == 0 {
			// A pinned flag names the one layout the key proves.
			api.AssertIsEqual(flag, fixed>>i&1)
		}
	}
	return l
}

func (l Layout) Flag(f int) frontend.Variable {
	return l.flags[bits.TrailingZeros(uint(f))]
}
