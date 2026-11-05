// Screens a ring deposit through the rule sections a transfer runs.
//
// A deposit enters through SPP's public slots, spends no note and has no ring sender. The rules still
// bind what it creates, a blocked recipient or a delisted asset would otherwise enter the ring through
// public funds.
//
// Read after policy/rules.go, policy/credentials.go. Read before deposit.go.
//
// Properties:
// 1. While policy_hash is nonzero, every live recipient and deposited asset meets the rules under the bound roots.
// 2. Every deposit reads as a receipt, no input nets it, and its amount enters the guard totals.
// 3. Outflow stays clear, a deposit reads no cap and carries no approval bit.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// maxDepositAssets is SPP's MAX_DEPOSIT_ASSETS, DepositAccounts::validate_and_parse refuses more.
const maxDepositAssets = 5

// NewDepositPolicy holds one record per recipient, per asset SPP admits and per salted key, no sender, leg or public slot reads the pools.
func NewDepositPolicy(deposits, saltedKeys int) (Policy, error) {
	records := deposits + min(deposits, maxDepositAssets) + saltedKeys
	return NewPolicy(InputsShape{Outputs: deposits, SaltedKeys: saltedKeys}.Inputs(), RecordPoolShape{Own: records, Curator: records}, 0)
}

// ScreenDeposit runs the payment section alone, public funds spend no input and every deposit reads as a receipt.
func (p *Policy) ScreenDeposit(api frontend.API, rc frontend.Rangechecker, credentials CredentialPool, deposits []shared.Output) {
	g := Rail{ThresholdsActive: 0, Delegate: 0}.Gates(api, p.PolicyHash)
	p.screenPayments(api, newComparator(rc), g, Spend{Credentials: credentials}, slotPayments(deposits))
}
