package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Senders follow the rail's owner predicates.
type Spend struct {
	Senders []frontend.Variable
	Inputs  []shared.Output
	// Tracking binds each owner's salt.
	Tracking TrackingPool
}

// ApprovalMask reads zero while Outflow is off.
type Screening struct {
	ApprovalMask frontend.Variable
	// Asset, peak and outflow per output slot, then asset, peak, outflow and gross per public slot, mirrored by ApprovalTotals in program-libs/policy/src/approval_totals.rs.
	totals  []frontend.Variable
	outflow frontend.Variable
}

// AssertApprovalTotals binds a nonzero commitment to the totals, a co-signer opens it off chain and zero discloses nothing.
func (s Screening) AssertApprovalTotals(api frontend.API, commitment, blinder frontend.Variable) {
	disclosed := ringgadget.IsNonZero(api, commitment)
	hash := gadget.HashChain4(api, append([]frontend.Variable{shared.ApprovalTotalsDomain, blinder}, s.totals...))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: disclosed, A: commitment, B: hash})
	// Off the outflow section the gross reads zero, a charge would read short.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, s.outflow), V: disclosed})
}

func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, g Gates, spend Spend, outputs []shared.Output) Screening {
	cmp := newComparator(rc)
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	p.assertOwnOnly(api)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	resolved := p.resolveSubjects(api, rc, table, g, spend, payments)
	active := screenedRules(api, g.Screened, table)
	// The sender section reads the rows, a deposit has none.
	assertRowsAscending(api, g.Rows, spend.Senders, resolved.liveSenders)
	assertSenderRules(api, active, table, resolved)
	assertPaymentRules(api, cmp, active, table, resolved, payments, spend.Inputs)
	// The outflow section binds on a ring with an own registry, with or without a policy hash.
	return p.constrainOutflow(api, cmp, g.Outflow, spend, outputs, resolved)
}
