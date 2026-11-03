// Runs every policy section of one transfer under the gates the statement
// fixes. A gate off removes only its predicates, the section's hashing,
// decoding and lookups still constrain the witness.
//
// Read after policy/subjects.go, policy/rules.go, policy/outflow.go,
// policy/exemption.go. Read before transfer/confidential.go.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Screen applies every policy section under the rail's gates, the approval it returns is zero while Outflow is off.
func (p *Policy) Screen(api frontend.API, rc frontend.Rangechecker, rail Rail, sender frontend.Variable, outputs []shared.Output) frontend.Variable {
	cmp := p.comparator(rc)
	g := rail.gates(api, p.PolicyHash)
	// 1. The rules read the table under policy_hash while screened.
	table := p.Table.decodeWhen(api, rc, g.Screened, p.PolicyHash)
	p.assertOwnOnly(api)
	// 2. Each recipient is its slot's owner identity while screened and published, zero otherwise.
	p.assertRecipients(api, g.Screened, g.Published, outputs)
	// 3. Every live withdrawal leg is a payment the program hashed.
	payments := append(slotPayments(outputs), p.openWithdrawals(api, rc)...)
	// 4. The subjects each gate activates open under own_root, and under curator_root when a list is foreign.
	resolved := p.resolveSubjects(api, table, g, sender, payments, len(outputs))
	// 5. Every enabled rule holds for its subjects while screened.
	p.assertRules(api, cmp, g.Screened, table, resolved, payments)
	// 6. Every limit row bounds the outflow while Outflow is on, the approval says whether one passes its co-sign bound.
	approval := p.constrainOutflow(api, cmp, g.Outflow, sender, outputs, resolved)
	// 7. Every public slot's gross withdrawal stays within its record's threshold while exempt.
	p.assertExemption(api, cmp, g.Exempt, resolved.publicAssets)
	// 8. Under key escrow every output owner escrows the output's nullifier key.
	p.assertEscrow(api, g.KeyEscrow, resolved.owners, outputs)
	return approval
}
