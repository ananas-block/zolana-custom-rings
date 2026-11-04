package policy

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type mintPolicyWires struct{ threshold, cap, cosignAbove frontend.Variable }

type publicAsset struct {
	limitedAsset
	// withdrawalThreshold reads zero off a record.
	withdrawalThreshold frontend.Variable
}

// debitBits bounds every amount sum the policy compares, SPP's range checks bind input amounts through their hash and UintBytesBE output amounts.
const debitBits = 72

// Approval mask bits, mirrored by ApprovalMask in program-libs/policy/src/quantities.rs.
const (
	ApprovalOutflow    = 1
	ApprovalWithdrawal = 2
)

// Every output and public asset opens its own record, including absence.
type limitedAsset struct {
	asset, active frontend.Variable
	policy        mintPolicyWires
}

// held = debit + kept.
type ownerFlow struct{ debit, kept, charge, outflow frontend.Variable }

type assetTotals struct{ peak, outflow frontend.Variable }

type flowSource struct {
	inputs, outputs []shared.Output
	// Keyed by row then slot.
	heldBy, returnedBy [][]frontend.Variable
	// Zero on a zero owner, a zero row matches it.
	held, returned []frontend.Variable
	exits          []frontend.Variable
	publicAssets   []frontend.Variable
	// Statement-bound, the screened legs are empty off a policy.
	gross []frontend.Variable
}

// constrainOutflow holds each row's outflow per asset to the asset's cap, the proven approval mask reads zero while active is off.
func (p *PolicyInputs) constrainOutflow(api frontend.API, cmp comparator, active frontend.Variable, spend Spend, outputs []shared.Output, resolved subjects) Screening {
	gross := make([]frontend.Variable, len(p.PublicGross))
	for k := range gross {
		// An active gross lies below 2^64 as the comparator needs, an inactive one is unread.
		gross[k] = api.Mul(active, p.PublicGross[k])
		cmp.rc.Check(gross[k], transaction.AmountBits)
	}
	source := newFlowSource(api, spend, outputs, p.PublicAssets[:], gross)
	overOutflow := frontend.Variable(0)
	bound := func(limit limitedAsset, flows []ownerFlow) assetTotals {
		outflows, total := make([]frontend.Variable, len(flows)), frontend.Variable(0)
		for j, flow := range flows {
			outflows[j] = flow.outflow
			total = api.Add(total, flow.outflow)
		}
		peak := cmp.peak(api, outflows)
		bounded := api.Mul(active, limit.active)
		transaction.AssertWhen(api, api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cap)), cmp.atMost(api, peak, limit.policy.cap))
		cosigned := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cosignAbove))
		overOutflow = api.Or(overOutflow, api.Mul(cosigned, cmp.above(api, peak, limit.policy.cosignAbove)))
		return assetTotals{peak: peak, outflow: total}
	}
	totals := make([]frontend.Variable, 0, 3*len(outputs)+4*len(resolved.publicAssets))
	for o, out := range outputs {
		slot := bound(limitedAsset{asset: out.Asset, active: out.Utxo, policy: resolved.mintPolicies[o]}, source.flowsOf(api, cmp, out.Asset))
		// A dummy keeps its asset and may share a live one, zeros keep its slot from reading as live.
		totals = append(totals, api.Mul(out.Utxo, out.Asset), api.Mul(out.Utxo, slot.peak), api.Mul(out.Utxo, slot.outflow))
	}
	for k, public := range resolved.publicAssets {
		// An asset any row keeps is a live output's asset, whose flow above holds the charge.
		slot := bound(public.limitedAsset, source.splitOf(api, cmp, source.flagsOf(api, public.asset)).rows)
		totals = append(totals, public.asset, slot.peak, slot.outflow, gross[k])
	}
	overWithdrawal := frontend.Variable(0)
	for k, asset := range resolved.publicAssets {
		threshold := api.Mul(active, asset.withdrawalThreshold)
		cmp.rc.Check(threshold, transaction.AmountBits)
		watched := api.Mul(active, asset.active, ringgadget.IsNonZero(api, threshold))
		overWithdrawal = api.Or(overWithdrawal, api.Mul(watched, cmp.above(api, gross[k], threshold)))
	}
	return Screening{
		ApprovalMask: api.Add(api.Mul(ApprovalOutflow, overOutflow), api.Mul(ApprovalWithdrawal, overWithdrawal)),
		totals:       totals,
		outflow:      active,
	}
}

func newFlowSource(api frontend.API, spend Spend, outputs []shared.Output, publicAssets, gross []frontend.Variable) flowSource {
	// A default-ring input is a held input.
	held, heldBy := ownedAmounts(api, spend.Senders, spend.Inputs, func(input shared.Output) frontend.Variable { return input.Utxo })
	// An exit reads no Ring flag, it leaves the ring whoever receives it.
	returned, returnedBy := ownedAmounts(api, spend.Senders, outputs, func(out shared.Output) frontend.Variable { return out.Ring })
	exits := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		exits[o] = api.Mul(out.Exit, out.Amount)
	}
	return flowSource{
		inputs: spend.Inputs, outputs: outputs,
		heldBy: heldBy, returnedBy: returnedBy,
		held: held, returned: returned, exits: exits,
		publicAssets: publicAssets, gross: gross,
	}
}

// flowsOf attributes the asset's displaced amount over the rows in their constrained order, no prover input selects a share.
func (s flowSource) flowsOf(api frontend.API, cmp comparator, asset frontend.Variable) []ownerFlow {
	flags := s.flagsOf(api, asset)
	leaving := frontend.Variable(0)
	for o, exit := range s.exits {
		leaving = api.Add(leaving, api.Mul(flags.outputs[o], exit))
	}
	for k, public := range s.publicAssets {
		leaving = api.Add(leaving, api.Mul(api.IsZero(api.Sub(public, asset)), s.gross[k]))
	}
	split := s.splitOf(api, cmp, flags)
	flows := split.rows
	// displaced <= split.kept since split.debit + split.kept = split.held, a zero kept total forces a zero displaced and a divisor of one.
	displaced := api.Sub(cmp.min(api, leaving, split.held), cmp.min(api, leaving, split.debit))
	divisor := api.Add(split.kept, api.IsZero(split.kept))
	// Running floors telescope to displaced so charge <= kept, the last floor is displaced itself.
	running, previous := frontend.Variable(0), frontend.Variable(0)
	for j := range flows {
		share := displaced
		if j < len(flows)-1 {
			running = api.Add(running, flows[j].kept)
			share = cmp.floorDiv(api, api.Mul(displaced, running), divisor)
		}
		flows[j].charge = api.Sub(share, previous)
		flows[j].outflow = api.Add(flows[j].debit, flows[j].charge)
		previous = share
	}
	return flows
}

type slotFlags struct{ inputs, outputs []frontend.Variable }

func (s flowSource) flagsOf(api frontend.API, asset frontend.Variable) slotFlags {
	return slotFlags{inputs: assetFlags(api, asset, s.inputs), outputs: assetFlags(api, asset, s.outputs)}
}

type assetSplit struct {
	// A row's outflow reads its debit until flowsOf charges it.
	rows              []ownerFlow
	held, debit, kept frontend.Variable
}

func (s flowSource) splitOf(api frontend.API, cmp comparator, flags slotFlags) assetSplit {
	heldAmounts, returnedAmounts := weighted(api, s.held, flags.inputs), weighted(api, s.returned, flags.outputs)
	split := assetSplit{rows: make([]ownerFlow, len(s.heldBy)), held: 0, debit: 0, kept: 0}
	for j := range split.rows {
		held := innerProduct(api, s.heldBy[j], heldAmounts)
		debit := cmp.saturatingSub(api, held, innerProduct(api, s.returnedBy[j], returnedAmounts))
		kept := api.Sub(held, debit)
		split.rows[j] = ownerFlow{debit: debit, kept: kept, charge: 0, outflow: debit}
		split.held, split.debit, split.kept = api.Add(split.held, held), api.Add(split.debit, debit), api.Add(split.kept, kept)
	}
	return split
}

// Keyed by identity alone, a zero owner reads no amount so a zero row holds nothing.
func ownedAmounts(api frontend.API, rows []frontend.Variable, slots []shared.Output, flag func(shared.Output) frontend.Variable) (amounts []frontend.Variable, ownedBy [][]frontend.Variable) {
	amounts, ownedBy = make([]frontend.Variable, len(slots)), make([][]frontend.Variable, len(rows))
	for i, slot := range slots {
		amounts[i] = api.Mul(flag(slot), ringgadget.IsNonZero(api, slot.OwnerPkHash), slot.Amount)
	}
	for j, row := range rows {
		ownedBy[j] = make([]frontend.Variable, len(slots))
		for i, slot := range slots {
			ownedBy[j][i] = api.IsZero(api.Sub(slot.OwnerPkHash, row))
		}
	}
	return amounts, ownedBy
}

func assetFlags(api frontend.API, asset frontend.Variable, slots []shared.Output) []frontend.Variable {
	flags := make([]frontend.Variable, len(slots))
	for i, slot := range slots {
		flags[i] = api.IsZero(api.Sub(slot.Asset, asset))
	}
	return flags
}

func weighted(api frontend.API, values, flags []frontend.Variable) []frontend.Variable {
	products := make([]frontend.Variable, len(values))
	for i, value := range values {
		products[i] = api.Mul(value, flags[i])
	}
	return products
}

func innerProduct(api frontend.API, values, flags []frontend.Variable) frontend.Variable {
	total := frontend.Variable(0)
	for i, value := range values {
		total = api.Add(total, api.Mul(value, flags[i]))
	}
	return total
}

// assertRowsAscending holds live rows strictly ascending with zero rows last, attribution reads the order and a repeated row would count its funds twice.
func assertRowsAscending(api frontend.API, enabled frontend.Variable, rows, liveRows []frontend.Variable) {
	for j := 1; j < len(rows); j++ {
		ringgadget.AssertOrderedWhen(api, api.Mul(enabled, liveRows[j]), 0, rows[j-1], rows[j])
	}
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

func init() { solver.RegisterHint(divisionHint, peakHint) }

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
