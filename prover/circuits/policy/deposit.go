package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// maxDepositAssets is SPP's MAX_DEPOSIT_ASSETS, DepositAccounts::validate_and_parse refuses more.
const maxDepositAssets = 5

// NewDepositPolicy holds a public and a salted record per recipient and one per asset SPP admits, no sender, leg or public slot reads the pools.
func NewDepositPolicy(deposits int) (Policy, error) {
	records := 2*deposits + min(deposits, maxDepositAssets)
	inputs := InputsShape{Outputs: deposits}.Inputs()
	inputs.SaltedKeys = deposits
	return NewPolicy(inputs, RecordPoolShape{Own: records, Curator: records}, 0)
}

// ScreenDeposit runs the payment section alone, public funds spend no input and every deposit reads as a receipt.
func (p *Policy) ScreenDeposit(api frontend.API, rc frontend.Rangechecker, tracking TrackingPool, deposits []shared.Output) {
	g := Rail{ThresholdsActive: 0, Delegate: 0}.Gates(api, p.PolicyHash)
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	payments := slotPayments(deposits)
	resolved := p.resolveSubjects(api, rc, table, g, Spend{Tracking: tracking}, payments)
	assertPaymentRules(api, newComparator(rc), screenedRules(api, g.Screened, table), table, resolved, payments, nil)
}
