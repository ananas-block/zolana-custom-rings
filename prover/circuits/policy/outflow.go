package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type mintPolicyWires struct{ threshold, cap, cosignAbove frontend.Variable }

func decodeMintPolicy(api frontend.API, packed frontend.Variable) mintPolicyWires {
	bits := api.ToBinary(packed, 192)
	return mintPolicyWires{api.FromBinary(bits[128:]...), api.FromBinary(bits[64:128]...), api.FromBinary(bits[:64]...)}
}

// Every output and public asset opens its own record, including absence. The
// transaction, rather than a sender-supplied list of limits, determines coverage.
func (p *Policy) constrainOutflow(api frontend.API, cmp comparator, sender frontend.Variable, outputs []utxoView, policies []mintPolicyWires) frontend.Variable {
	leaving := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		change := api.Mul(api.IsZero(api.Sub(out.ownerPkHash, sender)), api.IsZero(api.Sub(out.ringProgramID, p.RingProgramID)))
		leaving[o] = api.Mul(out.utxo, api.Sub(1, change), out.amount)
	}
	approval := frontend.Variable(0)
	check := func(asset, active frontend.Variable, policy mintPolicyWires) {
		others, net := frontend.Variable(0), frontend.Variable(0)
		for o, out := range outputs {
			others = api.Add(others, api.Mul(api.IsZero(api.Sub(out.asset, asset)), leaving[o]))
		}
		for k, publicAsset := range p.PublicAssets {
			net = api.Add(net, api.Mul(api.IsZero(api.Sub(publicAsset, asset)), p.PublicAmounts[k]))
		}
		limited := api.Mul(active, api.Or(ringgadget.IsNonZero(api, policy.cap), ringgadget.IsNonZero(api, policy.cosignAbove)))
		transaction.AssertWhen(api, limited, cmp.atMost(api, net, others))
		outflow := api.Sub(others, net)
		transaction.AssertWhen(api, api.Mul(active, ringgadget.IsNonZero(api, policy.cap)), cmp.atMost(api, outflow, policy.cap))
		cosigned := api.Mul(active, ringgadget.IsNonZero(api, policy.cosignAbove))
		approval = api.Or(approval, api.Mul(cosigned, api.Sub(1, cmp.atMost(api, outflow, policy.cosignAbove))))
	}
	for o, out := range outputs {
		check(out.asset, out.utxo, policies[o])
	}
	for k, asset := range p.PublicAssets {
		active := ringgadget.IsNonZero(api, asset)
		_, _, packed, _ := p.PublicAssetEntries[k].Resolve(api, active, p.OwnRoot, asset)
		check(asset, active, decodeMintPolicy(api, packed))
	}
	return approval
}
