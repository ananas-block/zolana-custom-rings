package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Senders follow the rail's owner predicates.
type Spend struct {
	Senders []frontend.Variable
	Inputs  []shared.Output
}

// Approval reads zero while Outflow is off.
type Screening struct {
	Approval frontend.Variable
	// Address hashes read zero off a record.
	SenderAddress  frontend.Variable
	OwnerAddresses []frontend.Variable
}

func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, g Gates, spend Spend, outputs []shared.Output) Screening {
	cmp := p.comparator(rc)
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	p.assertOwnOnly(api)
	p.assertRecipients(api, g.Screened, g.Published, outputs)
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	escrows := escrowsOwed(api, g.KeyEscrow, outputs)
	resolved := p.resolveSubjects(api, table, g, spend.Senders, payments, escrows)
	active := screenedRules(api, g.Screened, table)
	assertSenderRules(api, active, table, resolved)
	assertPaymentRules(api, cmp, g.Screened, active, table, resolved, payments)
	approval := p.constrainOutflow(api, rc, g.Outflow, spend, outputs, resolved)
	p.assertExemption(api, cmp, g.Exempt, resolved.publicAssets)
	p.assertEscrow(api, escrows, resolved.owners, outputs)
	screening := Screening{Approval: approval, SenderAddress: resolved.senders[0].addressHash, OwnerAddresses: make([]frontend.Variable, len(outputs))}
	for o := range outputs {
		screening.OwnerAddresses[o] = resolved.owners[o].addressHash
	}
	return screening
}
