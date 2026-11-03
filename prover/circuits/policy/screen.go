package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Screen applies every policy section under the rail's gates, the approval it returns is zero while Outflow is off.
func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, rail Rail, sender frontend.Variable, outputs []shared.Output) frontend.Variable {
	cmp := p.comparator(rc)
	g := rail.gates(api, p.PolicyHash)
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	p.assertOwnOnly(api)
	p.assertRecipients(api, g.Screened, g.Published, outputs)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	resolved := p.resolveSubjects(api, table, g, sender, payments, len(outputs))
	p.assertRules(api, cmp, g.Screened, table, resolved, payments)
	approval := p.constrainOutflow(api, cmp, g.Outflow, sender, outputs, resolved)
	p.assertExemption(api, cmp, g.Exempt, resolved.publicAssets)
	p.assertEscrow(api, g.KeyEscrow, resolved.owners, outputs)
	return approval
}
