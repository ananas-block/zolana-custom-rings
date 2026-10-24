package ringgadget

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
)

const gapLimbBits = 128

// AssertOrderedWhen proves lo < mid < hi over canonical field integers while a boolean enabled is set,
// the gaps lo, mid-lo-1, hi-mid-1 and q-1-hi summing to q-3 without a wrap.
func AssertOrderedWhen(api frontend.API, enabled, lo, mid, hi frontend.Variable) {
	q := api.Compiler().Field()
	if q.BitLen() <= gapLimbBits+3 || q.BitLen() > 2*gapLimbBits {
		panic("ordered when: native field outside 132..256 bits")
	}
	// 1. The caller's boolean flag either keeps the operands or swaps in the satisfiable 0 < 1 < 2.
	lo = api.Mul(enabled, lo)
	mid = api.Add(api.Mul(enabled, api.Sub(mid, 1)), 1)
	hi = api.Add(api.Mul(enabled, api.Sub(hi, 2)), 2)
	w, err := api.Compiler().NewHint(orderedGapsHint, 9, lo, mid, hi)
	if err != nil {
		panic(err)
	}
	limbs, carry := w[:8], w[8]
	// 2. Bounded limbs keep both sums below 2^131, far below q, so they hold over the integers.
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, gapLimbBits)
	}
	rc.Check(carry, 2)
	// 3. The four gaps plus 2 equal q-1 exactly, so each gap and each partial sum is below q.
	base := new(big.Int).Lsh(big.NewInt(1), gapLimbBits)
	limit := new(big.Int).Sub(q, big.NewInt(1))
	limitLow := new(big.Int).And(limit, new(big.Int).Sub(base, big.NewInt(1)))
	limitHigh := new(big.Int).Rsh(limit, gapLimbBits)
	api.AssertIsEqual(api.Add(limbs[0], limbs[2], limbs[4], limbs[6], 2), api.Add(limitLow, api.Mul(base, carry)))
	api.AssertIsEqual(api.Add(limbs[1], limbs[3], limbs[5], limbs[7], carry), limitHigh)
	// 4. The gaps rebuild lo, mid and hi with a step of at least one between neighbours.
	gap := func(i int) frontend.Variable { return api.Add(limbs[2*i], api.Mul(base, limbs[2*i+1])) }
	api.AssertIsEqual(gap(0), lo)
	api.AssertIsEqual(api.Add(lo, gap(1), 1), mid)
	api.AssertIsEqual(api.Add(mid, gap(2), 1), hi)
}

func init() { solver.RegisterHint(orderedGapsHint) }

// orderedGapsHint proposes the gap limbs and the low limb carry, untrusted until
// AssertOrderedWhen range-checks and recomposes them.
func orderedGapsHint(q *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 3 || len(outputs) != 9 {
		return errors.New("ordered gaps: expected 3 inputs and 9 outputs")
	}
	one := big.NewInt(1)
	gaps := []*big.Int{
		new(big.Int).Set(inputs[0]),
		new(big.Int).Sub(new(big.Int).Sub(inputs[1], inputs[0]), one),
		new(big.Int).Sub(new(big.Int).Sub(inputs[2], inputs[1]), one),
		new(big.Int).Sub(new(big.Int).Sub(q, one), inputs[2]),
	}
	mask := new(big.Int).Sub(new(big.Int).Lsh(one, gapLimbBits), one)
	carry := big.NewInt(2)
	for i, gap := range gaps {
		// An unordered input leaves a negative gap, zero keeps the hint total and the circuit refuses it.
		if gap.Sign() < 0 {
			gap.SetInt64(0)
		}
		outputs[2*i].And(gap, mask)
		outputs[2*i+1].Rsh(gap, gapLimbBits)
		carry.Add(carry, outputs[2*i])
	}
	outputs[8].Rsh(carry, gapLimbBits)
	return nil
}
