// Compares, divides and takes a peak over the integers the policy sums.
//
// A field wraps, and a bare subtraction cannot tell a small difference from a large one. atMost and
// floorDiv take values from a hint and hold them with range checks and a recomposition far below q, so
// the equation holds over the integers and the split is unique. peak holds its hint with range checked
// gaps and a zero product. The rules and the outflow section both read through these forms, a wrong bound
// here would pass a total over any threshold or cap.
//
// Read after policy/rules.go. Read before policy/outflow.go.
//
// Properties:
// 1. atMost returns total <= threshold over the integers, its caller bounding the difference below 2^width in magnitude.
// 2. floorDiv returns the one quotient of numerator and divisor, its caller bounding both.
// 3. peak returns the largest of its values, its caller bounding each.

package policy

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// debitBits bounds every amount sum the policy compares, SPP's range checks bind input amounts through their hash and UintBytesBE output amounts.
// Leg amounts and the gross take their own range checks. Shapes and DepositCapacities hold a key under 64 inputs and 64 payments, so one side's sum of u64 amounts stays below 2^70. Distinct rows keep a total over rows on the same bound, repeated rows on the authority rail can only leave their own proof unsolvable.
const debitBits = 72

type comparator struct {
	rc frontend.Rangechecker
	// width bounds every difference the key compares, fixed when the key compiles.
	width int
}

func newComparator(rc frontend.Rangechecker) comparator {
	return comparator{rc: rc, width: debitBits}
}

// atMost returns total <= threshold, the caller bounds their difference below 2^width in magnitude.
func (c comparator) atMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	offset := new(big.Int).Lsh(big.NewInt(1), uint(c.width))
	delta := api.Add(api.Sub(threshold, total), offset)
	// 1. The hint proposes the low width bits and the top bit of delta, untrusted until the checks below bind them.
	parts, err := api.Compiler().NewHint(comparisonHint, 2, delta, c.width)
	if err != nil {
		panic(err)
	}
	low, top := parts[0], parts[1]
	// 2. low below 2^width leaves one split per delta.
	c.rc.Check(low, c.width)
	// 3. top is a bit, the split then covers delta below 2^(width+1) only.
	api.AssertIsBoolean(top)
	// 4. delta lies in (0, 2^(width+1)), its split is unique and top is set exactly when total <= threshold.
	api.AssertIsEqual(delta, api.Add(low, api.Mul(top, offset)))
	return top
}

// The callers of min, above and saturatingSub bound the difference as atMost needs.
func (c comparator) min(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(c.atMost(api, a, b), a, b)
}

func (c comparator) above(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	return api.Sub(1, c.atMost(api, total, threshold))
}

func (c comparator) saturatingSub(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(c.atMost(api, a, b), 0, api.Sub(a, b))
}

// floorDiv returns numerator / divisor rounded down, the caller holds divisor in [1, 2^width) and numerator below 2^(2*width).
func (c comparator) floorDiv(api frontend.API, numerator, divisor frontend.Variable) frontend.Variable {
	parts, err := api.Compiler().NewHint(divisionHint, 2, numerator, divisor)
	if err != nil {
		panic(err)
	}
	quotient, remainder := parts[0], parts[1]
	c.rc.Check(quotient, c.width)
	c.rc.Check(remainder, c.width)
	// remainder < divisor, both bounded so the difference cannot wrap.
	c.rc.Check(api.Sub(divisor, 1, remainder), c.width)
	// Both sides stay far below the field, the equation holds over the integers and the split is unique.
	api.AssertIsEqual(numerator, api.Add(api.Mul(quotient, divisor), remainder))
	return quotient
}

// The caller holds each value below 2^width.
func (c comparator) peak(api frontend.API, values []frontend.Variable) frontend.Variable {
	parts, err := api.Compiler().NewHint(peakHint, 1, values...)
	if err != nil {
		panic(err)
	}
	// Every value lies at or under the peak and one equals it.
	product := frontend.Variable(1)
	for _, value := range values {
		gap := api.Sub(parts[0], value)
		c.rc.Check(gap, c.width)
		product = api.Mul(product, gap)
	}
	api.AssertIsEqual(product, 0)
	return parts[0]
}

func init() { solver.RegisterHint(comparisonHint, divisionHint, peakHint) }

// comparisonHint splits delta at the width, atMost range checks and recomposes both parts.
func comparisonHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("comparison: want delta, width and two outputs")
	}
	width := uint(inputs[1].Uint64())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], width)
	return nil
}

// divisionHint proposes a quotient and remainder, floorDiv range checks and recomposes both.
func divisionHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || inputs[1].Sign() == 0 {
		return errors.New("division wants numerator, nonzero divisor and two outputs")
	}
	outputs[0].DivMod(inputs[0], inputs[1], outputs[1])
	return nil
}

// Untrusted until peak bounds it from both sides.
func peakHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(outputs) != 1 {
		return errors.New("peak wants one output")
	}
	for _, input := range inputs {
		if input.Cmp(outputs[0]) > 0 {
			outputs[0].Set(input)
		}
	}
	return nil
}
