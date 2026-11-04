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

// Screen holds a spend to the policy, withdrawal legs join the payments only once their hash binds them.
func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, g Gates, spend Spend, outputs []shared.Output) Screening {
	cmp := newComparator(rc)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	resolved := p.screenPayments(api, cmp, g, spend, payments)
	// The outflow section binds on a ring with an own registry, with or without a policy hash.
	return p.constrainOutflow(api, cmp, g.Outflow, spend, outputs, resolved)
}

// screenPayments runs the rule sections of a transfer and a deposit over one flow, a deposit's Spend has no row and no input and those sections stay out of its key.
func (p *Policy) screenPayments(api frontend.API, cmp comparator, g Gates, spend Spend, payments []Payment) subjects {
	// 1. While Screened, the table is the one the program hashed at policy_hash. A clear table binds nothing because every rule below reads through the same gate.
	table := p.Table.decodeWhen(api, cmp.rc, g.Screened, p.PolicyHash)
	// 2. Every subject now holds list bits its registry's root authenticates, so the rule sections can trust a view without reading a proof.
	resolved := p.resolveSubjects(api, table, g, spend, payments)
	active := screenedRules(api, g.Screened, table)
	// 3. The rows are strictly ascending with zero rows last, and every live row meets every sender rule. Attribution in the outflow section relies on the order, a repeated row would count its funds twice.
	assertRowsAscending(api, g.Rows, spend.Senders, resolved.liveSenders)
	assertSenderRules(api, active, table, resolved)
	// 4. Every live payment's owner and asset meet their rules within the guard totals, the only section where amounts decide a rule.
	assertPaymentRules(api, cmp, active, table, resolved, payments, spend.Inputs)
	// 5. Every live input's asset meets the unconditional asset rules, list bits alone decide and no amount enters a total.
	assertInputAssetRules(api, active, table, resolved)
	return resolved
}
