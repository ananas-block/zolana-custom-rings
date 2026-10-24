package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
)

const WithdrawalDomain = 0x43525057 // CRPW

// WithdrawalWires names the screened owner, asset and gross amount of a public leg.
// These payments do not enter private_tx_hash, escrow or net outflow a second time.
type WithdrawalWires struct{ Owner, Asset, Amount frontend.Variable }

func (p *Policy) openWithdrawals(api frontend.API, rc frontend.Rangechecker) []utxoView {
	count := ringgadget.SelectCount(api, p.WithdrawalCount, 0, len(p.Withdrawals)+1)
	fields := []frontend.Variable{WithdrawalDomain, p.WithdrawalCount}
	ends := make([]frontend.Variable, 2+3*len(p.Withdrawals))
	for i := range ends {
		ends[i] = 0
	}
	ends[1] = count.OneHot[0]
	payments := make([]utxoView, len(p.Withdrawals))
	for i, w := range p.Withdrawals {
		active := count.Active[i]
		rc.Check(w.Amount, 64)
		api.AssertIsEqual(api.Mul(active, api.IsZero(w.Amount)), 0)
		api.AssertIsEqual(api.Mul(active, api.IsZero(w.Asset)), 0)
		for _, v := range []frontend.Variable{w.Owner, w.Asset, w.Amount} {
			api.AssertIsEqual(api.Mul(api.Sub(1, active), v), 0)
		}
		fields = append(fields, w.Owner, w.Asset, w.Amount)
		ends[4+3*i] = count.OneHot[i+1]
		payments[i] = utxoView{ownerPkHash: w.Owner, asset: w.Asset, amount: w.Amount, utxo: active}
	}
	api.AssertIsEqual(p.WithdrawalHash, ringgadget.HashPrefix4(api, fields, ends))
	return payments
}
