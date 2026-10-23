// Package ringgadget holds the generic gadgets the ring circuits add to zolana's gadget package.
package ringgadget

import (
	"github.com/consensys/gnark/frontend"
)

const byteBits = 8

// BoundedBytes skips the byte check, for bytes the caller constrains to 8 bits where they are produced.
type BoundedBytes struct{}

func (BoundedBytes) Check(frontend.Variable, int) {}

func IsConstantZero(api frontend.API, v frontend.Variable) bool {
	value, ok := api.Compiler().ConstantValue(v)
	return ok && value.Sign() == 0
}
