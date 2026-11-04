package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Senders follow the rail's owner predicates.
type Spend struct {
	Senders []frontend.Variable
	Inputs  []shared.Output
	// Tracking binds each private row's salt, unread on a key with no rows.
	Tracking TrackingPool
}

// ApprovalMask reads zero while Outflow is off.
type Screening struct {
	ApprovalMask frontend.Variable
}

func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, g Gates, spend Spend, outputs []shared.Output) Screening {
	cmp := newComparator(rc)
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	p.assertOwnOnly(api)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	resolved := p.resolveSubjects(api, rc, table, g, spend, payments)
	active := screenedRules(api, g.Screened, table)
	// 1. The sender section reads the rows, a deposit has none.
	assertRowsAscending(api, g.Rows, spend.Senders, resolved.liveSenders)
	assertSenderRules(api, active, table, resolved)
	// 2. The payment section is the one a deposit shares.
	assertPaymentRules(api, cmp, active, table, resolved, payments, spend.Inputs)
	// 3. The outflow section binds on a ring with an own registry, with or without a policy hash.
	mask := p.constrainOutflow(api, cmp, g.Outflow, spend, outputs, resolved)
	return Screening{ApprovalMask: mask}
}
