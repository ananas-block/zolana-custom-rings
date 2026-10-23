package ringgadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// SplitField returns high and low of value = high*2^lowBits + low, never the split of value+q.
func SplitField(api frontend.API, rc frontend.Rangechecker, value frontend.Variable, lowBits int) (high, low frontend.Variable) {
	if lowBits < 1 || lowBits >= api.Compiler().Field().BitLen() {
		panic("split field: low width outside the field")
	}
	out, err := api.Compiler().NewHint(splitFieldHint, 2, value, lowBits)
	if err != nil {
		panic(err)
	}
	high, low = out[0], out[1]
	rc.Check(low, lowBits)
	assertCanonicalSplit(api, rc, value, high, low, lowBits)
	return high, low
}

// assertCanonicalSplit pins value = high*2^lowBits + low below q, the caller bounds low to lowBits.
func assertCanonicalSplit(api frontend.API, rc frontend.Rangechecker, value, high, low frontend.Variable, lowBits int) {
	q := api.Compiler().Field()
	// Without the bound, a high near q wraps qHigh - high into range.
	rc.Check(high, q.BitLen()-lowBits)
	api.AssertIsEqual(value, api.Add(api.Mul(high, new(big.Int).Lsh(big.NewInt(1), uint(lowBits))), low))
	qHigh := new(big.Int).Rsh(q, uint(lowBits))
	qLow := new(big.Int).Sub(q, new(big.Int).Lsh(qHigh, uint(lowBits)))
	// high is at most the high part of q.
	rc.Check(api.Sub(qHigh, high), qHigh.BitLen())
	atBound := api.IsZero(api.Sub(high, qHigh))
	// At the high part of q, low stays below the low part of q.
	rc.Check(api.Mul(atBound, api.Sub(new(big.Int).Sub(qLow, big.NewInt(1)), low)), lowBits)
}

func init() { solver.RegisterHint(splitFieldHint) }

func splitFieldHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("split field: expecting a value, a low width and two outputs")
	}
	lowBits := uint(inputs[1].Uint64())
	outputs[0].Rsh(inputs[0], lowBits)
	outputs[1].Sub(inputs[0], new(big.Int).Lsh(outputs[0], lowBits))
	return nil
}
