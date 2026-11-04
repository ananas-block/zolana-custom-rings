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

type flowSource struct {
	inputs, outputs []shared.Output
	// Keyed by row then slot.
	held, returned [][]frontend.Variable
	publicAssets   []frontend.Variable
	// Statement-bound, the screened legs are empty off a policy.
	gross []frontend.Variable
}

// constrainOutflow holds each row's outflow per asset to the asset's cap and returns the proven approval mask, zero while active is off.
func (p *PolicyInputs) constrainOutflow(api frontend.API, cmp comparator, active frontend.Variable, spend Spend, outputs []shared.Output, resolved subjects) frontend.Variable {
	assets := make([]limitedAsset, 0, len(outputs)+len(resolved.publicAssets))
	for o, out := range outputs {
		assets = append(assets, limitedAsset{asset: out.Asset, active: out.Utxo, policy: resolved.mintPolicies[o]})
	}
	for _, public := range resolved.publicAssets {
		assets = append(assets, public.limitedAsset)
	}
	gross := make([]frontend.Variable, len(p.PublicGross))
	for k := range gross {
		// An active gross lies below 2^64 as the comparator needs, an inactive one is unread.
		gross[k] = api.Mul(active, p.PublicGross[k])
		cmp.rc.Check(gross[k], transaction.AmountBits)
	}
	source := newFlowSource(api, spend, resolved.liveSenders, outputs, p.PublicAssets[:], gross)
	overOutflow := frontend.Variable(0)
	for _, limit := range assets {
		bounded := api.Mul(active, limit.active)
		capped := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cap))
		cosigned := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cosignAbove))
		for _, flow := range source.flowsOf(api, cmp, limit.asset) {
			transaction.AssertWhen(api, capped, cmp.atMost(api, flow.outflow, limit.policy.cap))
			overOutflow = api.Or(overOutflow, api.Mul(cosigned, cmp.above(api, flow.outflow, limit.policy.cosignAbove)))
		}
	}
	overWithdrawal := frontend.Variable(0)
	for k, asset := range resolved.publicAssets {
		threshold := api.Mul(active, asset.withdrawalThreshold)
		cmp.rc.Check(threshold, transaction.AmountBits)
		watched := api.Mul(active, asset.active, ringgadget.IsNonZero(api, threshold))
		overWithdrawal = api.Or(overWithdrawal, api.Mul(watched, cmp.above(api, gross[k], threshold)))
	}
	return api.Add(api.Mul(ApprovalOutflow, overOutflow), api.Mul(ApprovalWithdrawal, overWithdrawal))
}

func newFlowSource(api frontend.API, spend Spend, liveRows []frontend.Variable, outputs []shared.Output, publicAssets, gross []frontend.Variable) flowSource {
	liveInputs, ringOutputs := make([]frontend.Variable, len(spend.Inputs)), make([]frontend.Variable, len(outputs))
	for i, input := range spend.Inputs {
		// A default-ring input is a held input.
		liveInputs[i] = input.Utxo
	}
	for o, out := range outputs {
		// An exit reads no Ring flag, it leaves the ring whoever receives it.
		ringOutputs[o] = out.Ring
	}
	return flowSource{
		inputs: spend.Inputs, outputs: outputs,
		held:         amountsByOwner(api, spend.Senders, liveRows, spend.Inputs, liveInputs),
		returned:     amountsByOwner(api, spend.Senders, liveRows, outputs, ringOutputs),
		publicAssets: publicAssets, gross: gross,
	}
}

// flowsOf attributes the asset's displaced amount over the rows in their constrained order, no prover input selects a share.
func (s flowSource) flowsOf(api frontend.API, cmp comparator, asset frontend.Variable) []ownerFlow {
	inputAssets, outputAssets := assetFlags(api, asset, s.inputs), assetFlags(api, asset, s.outputs)
	// 1. Every exit and public withdrawal of the asset leaves.
	leaving := frontend.Variable(0)
	for o, out := range s.outputs {
		leaving = api.Add(leaving, api.Mul(out.Exit, outputAssets[o], out.Amount))
	}
	for k, public := range s.publicAssets {
		leaving = api.Add(leaving, api.Mul(api.IsZero(api.Sub(public, asset)), s.gross[k]))
	}
	// 2. Each row splits its held funds into a net debit and the part returned to it.
	flows := make([]ownerFlow, len(s.held))
	sumHeld, sumDebit, sumKept := frontend.Variable(0), frontend.Variable(0), frontend.Variable(0)
	for j := range flows {
		held := innerProduct(api, s.held[j], inputAssets)
		returned := innerProduct(api, s.returned[j], outputAssets)
		debit := cmp.saturatingSub(api, held, returned)
		flows[j] = ownerFlow{debit: debit, kept: api.Sub(held, debit)}
		sumHeld, sumDebit, sumKept = api.Add(sumHeld, held), api.Add(sumDebit, debit), api.Add(sumKept, flows[j].kept)
	}
	// 3. displaced <= sumKept since sumDebit + sumKept = sumHeld, a zero sumKept forces a zero displaced and a divisor of one.
	displaced := api.Sub(cmp.min(api, leaving, sumHeld), cmp.min(api, leaving, sumDebit))
	divisor := api.Add(sumKept, api.IsZero(sumKept))
	// 4. The running floors telescope to displaced exactly, so no dust and charge <= kept.
	running, previous := frontend.Variable(0), frontend.Variable(0)
	for j := range flows {
		running = api.Add(running, flows[j].kept)
		share := cmp.floorDiv(api, api.Mul(displaced, running), divisor)
		flows[j].charge = api.Sub(share, previous)
		flows[j].outflow = api.Add(flows[j].debit, flows[j].charge)
		previous = share
	}
	return flows
}

// Keyed by identity alone, an owner's notes aggregate across nullifier keys, a zero row holds nothing.
func amountsByOwner(api frontend.API, rows, liveRows []frontend.Variable, slots []shared.Output, flags []frontend.Variable) [][]frontend.Variable {
	amounts := make([][]frontend.Variable, len(rows))
	for j, row := range rows {
		amounts[j] = make([]frontend.Variable, len(slots))
		for i, slot := range slots {
			amounts[j][i] = api.Mul(liveRows[j], flags[i], api.IsZero(api.Sub(slot.OwnerPkHash, row)), slot.Amount)
		}
	}
	return amounts
}

func assetFlags(api frontend.API, asset frontend.Variable, slots []shared.Output) []frontend.Variable {
	flags := make([]frontend.Variable, len(slots))
	for i, slot := range slots {
		flags[i] = api.IsZero(api.Sub(slot.Asset, asset))
	}
	return flags
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

func init() { solver.RegisterHint(divisionHint) }

// divisionHint proposes a quotient and remainder, floorDiv range checks and recomposes both.
func divisionHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || inputs[1].Sign() == 0 {
		return errors.New("division wants numerator, nonzero divisor and two outputs")
	}
	outputs[0].DivMod(inputs[0], inputs[1], outputs[1])
	return nil
}
