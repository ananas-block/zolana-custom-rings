// Package transfer proves a ring transfer's audit, policy and withdrawal exemption in one proof.
package transfer

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type auditStatementWires struct {
	FirstNullifier frontend.Variable
	TxViewingSk    [32]frontend.Variable
	EphSk          [32]frontend.Variable
	AuditorPk      [32]frontend.Variable
	Salt           [16]frontend.Variable
	Layout         frontend.Variable
}

func (w auditStatementWires) auditWires(ringProgramID frontend.Variable) audit.AuditWires {
	return audit.AuditWires{
		FirstNullifier: w.FirstNullifier,
		RingProgramID:  ringProgramID,
		TxViewingSk:    w.TxViewingSk,
		EphSk:          w.EphSk,
		AuditorPk:      w.AuditorPk,
		Salt:           w.Salt,
		Layout:         w.Layout,
	}
}

type screenedPolicy struct {
	Exempt, ApprovalRequired frontend.Variable
	policy.Policy
}

func (p *screenedPolicy) gates(api frontend.API, rail policy.Rail) policy.Gates {
	// Exempt switches assertExemption and the own pool lookups the thresholds read.
	api.AssertIsBoolean(p.Exempt)
	rail.Exempt = p.Exempt
	return rail.Gates(api, p.PolicyHash)
}

func (p *screenedPolicy) screen(api frontend.API, rc frontend.Rangechecker, g policy.Gates, spend policy.Spend, slots []shared.Output) policy.Screening {
	screening := p.Screen(api, rc, g, spend, slots)
	// Screen returns zero while Outflow is off, approval_required then reads the outflow's verdict alone.
	api.AssertIsEqual(p.ApprovalRequired, screening.Approval)
	return screening
}

// screenedOwners is the sender rows of the confidential and commitment keys, a policy refuses more distinct owners.
const screenedOwners = 4

// transactionBinding is SPP's private transaction hash and its blinding, the proof reopens the hash over the slots the audit opened.
type transactionBinding struct {
	PrivateTxHash     frontend.Variable
	PrivateTxBlinding frontend.Variable
}

// bindTransaction holds PrivateTxHash to Poseidon(input chain, output chain, 0, blinding), a ring transfer carries no address input.
func (b transactionBinding) bindTransaction(api frontend.API, inputChain frontend.Variable, outputs []shared.Output) {
	outputChain := gadget.NonZeroHashChain(api, shared.UtxoHashes(api, outputs))
	api.AssertIsEqual(b.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, 0, b.PrivateTxBlinding}))
}

// closeStatement binds the element count and the nonzero version last, a statement of another length or layout hashes apart.
func closeStatement(fields []frontend.Variable) []frontend.Variable {
	return append(fields, len(fields)+2, shared.TransferStatementVersion)
}

func publicSlots(assets, amounts, gross []frontend.Variable) []frontend.Variable {
	fields := make([]frontend.Variable, 0, 3*len(assets))
	for k := range assets {
		fields = append(fields, assets[k], amounts[k], gross[k])
	}
	return fields
}
