package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type mintPolicyWires struct{ threshold, cap, cosignAbove frontend.Variable }

type publicAsset struct {
	asset, active frontend.Variable
	policy        mintPolicyWires
	// withdrawalThreshold is the asset's own record's exemption bound, zero off a record.
	withdrawalThreshold frontend.Variable
}

// debitBits bounds every debit comparison, SPP's range checks bind input amounts through their hash and UintBytesBE output amounts.
const debitBits = 72

// Every output and public asset opens its own record, including absence.
type limitedAsset struct {
	asset, active frontend.Variable
	policy        mintPolicyWires
}

// constrainOutflow holds each sender's debit per asset to the asset's limits, credits never move between senders.
func (p *PolicyInputs) constrainOutflow(api frontend.API, rc frontend.Rangechecker, active frontend.Variable, spend Spend, outputs []shared.Output, resolved subjects) frontend.Variable {
	cmp := comparator{rc: rc, width: debitBits}
	assets := make([]limitedAsset, 0, len(outputs)+len(resolved.publicAssets))
	for o, out := range outputs {
		assets = append(assets, limitedAsset{asset: out.Asset, active: out.Utxo, policy: resolved.mintPolicies[o]})
	}
	for _, public := range resolved.publicAssets {
		assets = append(assets, limitedAsset{asset: public.asset, active: public.active, policy: public.policy})
	}
	liveInputs := make([]frontend.Variable, len(spend.Inputs))
	for i, input := range spend.Inputs {
		liveInputs[i] = input.Utxo
	}
	ringOutputs := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		// An exit reads no Ring flag, it leaves the ring whoever receives it.
		ringOutputs[o] = out.Ring
	}
	owned := amountsByOwner(api, spend.Senders, spend.Inputs, liveInputs)
	returned := amountsByOwner(api, spend.Senders, outputs, ringOutputs)
	approval := frontend.Variable(0)
	inputAssets := make([][]frontend.Variable, len(assets))
	for a, limit := range assets {
		inputAssets[a] = assetFlags(api, limit.asset, spend.Inputs)
		outputAssets := assetFlags(api, limit.asset, outputs)
		bounded := api.Mul(active, limit.active)
		capped := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cap))
		cosigned := api.Mul(bounded, ringgadget.IsNonZero(api, limit.policy.cosignAbove))
		for j := range spend.Senders {
			held := innerProduct(api, owned[j], inputAssets[a])
			kept := innerProduct(api, returned[j], outputAssets)
			debit := api.Select(cmp.atMost(api, held, kept), 0, api.Sub(held, kept))
			transaction.AssertWhen(api, capped, cmp.atMost(api, debit, limit.policy.cap))
			approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, cmp.atMost(api, debit, limit.policy.cosignAbove))))
		}
	}
	p.assertNoMixedDeposit(api, cmp, spend.Inputs, inputAssets[len(outputs):])
	return approval
}

// Keyed by identity alone, an owner's notes aggregate across nullifier keys.
func amountsByOwner(api frontend.API, senders []frontend.Variable, slots []shared.Output, flags []frontend.Variable) [][]frontend.Variable {
	amounts := make([][]frontend.Variable, len(senders))
	for j, sender := range senders {
		amounts[j] = make([]frontend.Variable, len(slots))
		for i, slot := range slots {
			amounts[j][i] = api.Mul(flags[i], api.IsZero(api.Sub(slot.OwnerPkHash, sender)), slot.Amount)
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

// assertNoMixedDeposit refuses a public deposit of a spent asset while the inputs span two owners, the deposit credits no single owner.
func (p *PolicyInputs) assertNoMixedDeposit(api frontend.API, cmp comparator, inputs []shared.Output, publicInputAssets [][]frontend.Variable) {
	// SPP's AssertDummiesLast leaves input 0 the first live input of any spend.
	mixed := frontend.Variable(0)
	for _, input := range inputs[1:] {
		mixed = api.Or(mixed, api.Mul(input.Utxo, api.Sub(1, api.IsZero(api.Sub(input.OwnerPkHash, inputs[0].OwnerPkHash)))))
	}
	for k, net := range p.PublicAmounts {
		// SPP's distinct u64 public slots keep net within u64 magnitude, the bound atMost needs.
		deposit := api.Sub(1, cmp.atMost(api, net, 0))
		// The flag count is zero exactly when no live input holds the deposited asset.
		spent := frontend.Variable(0)
		for i, input := range inputs {
			spent = api.Add(spent, api.Mul(input.Utxo, publicInputAssets[k][i]))
		}
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(mixed, deposit), V: spent})
	}
}
