// Proves one ring transfer in one proof. The auditor opens every note, the
// policy screens the sender and every payment, and an exemption bounds every
// withdrawal. The gates the program fixes in the statement switch only the
// predicates the properties name under them, every section's hashing,
// decoding and lookups constrain the witness on every rail.
//
// Read after audit/delivered.go, audit/anonymous.go, policy/screen.go. Read
// before prover/ring/ring.go.

// Package transfer proves a ring transfer's audit, policy and withdrawal exemption in one proof.
package transfer

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Local constraints, Define asserts them:
// 1. One opening of every output slot feeds the transaction binding, the auditor stream, the recipient bodies and the policy.
// 2. On every rail withdrawal_hash reopens over the legs, a live leg a nonzero amount of a nonzero asset, a leg past the count zero, every amount below 2^64.
// 3. While policy_hash is nonzero the table hashes to policy_hash and every enabled rule holds for the sender and, unless an amount guard exempts it, for every live payment's owner and asset.
// 4. Each recipient is its slot's owner identity while policy_hash is nonzero and the rail publishes, zero otherwise.
// 5. While policy_hash is nonzero and off the authority rail every limit row's outflow is never negative and within its cap, and approval_required is set exactly when one passes its co-sign bound, zero otherwise.
// 6. Under key_escrow every live output's owner record escrows the output's nullifier key.
// 7. Under exempt every public slot's gross withdrawal lies below 2^64 and, on a nonzero asset, at or under its asset record's threshold, zero off a record.
// 8. The own root is the own record pool's root while policy_hash is nonzero, key_escrow or exempt, the curator root is the curator pool's root while policy_hash is nonzero and a source is foreign.
// 9. On the authority rail in_proof and the statement's sender are zero, key escrow is on, and the policy screens the private SenderPkHash as the sender.
// 10. On the in-proof and authority rails input 0 is a UTXO, every spent UTXO lies below input_count and belongs to the sender and SPP's private transaction hash reopens over the opened inputs, on the signer rail every input is a dummy and the hash reopens over the input chain SPP proves.
// 11. On the anonymous rail the sender is spent UTXO 0's owner, or the owner of SenderKey on an entry key, and every party identity differs from it.
// 12. The one public input is HashChain4 of the statement the program rebuilds, its last element the nonzero version.
// 13. digest(envelope_ct) selects its length from input_count, the evidence selection reads the same count on the anonymous, in-proof and authority rails, the signer rail's envelope is tx_viewing_sk alone at any input_count.
// 14. exits_bitmap is the sum of Exit * 2^i over the opened slots.
//
// Program-derived facts, the statement fixes them:
// 15. input_count is the frame's nullifier count and exits_bitmap the frame's exit positions.
// 16. The rail bits come from the instruction, the layout from the config's key escrow and the key's family.
// 17. digest(envelope_ct) and output_ciphertext_chain hash the frame's bytes at the lengths family, layout, n_out, input_count, the bitmap and the rail bits fix.
//
// Guarantees the proof leans on:
// 18. PrivateTxHashCircuit in spp_transaction/shared/private_tx_hash.go commits exactly the outputs SPP settles to private_tx_hash, the binding here reopens that hash over the opened slots.
// 19. On the signer rail SPP authorizes the owner signer over every spent input, the proof reads no input opening there.
// 20. The Rust and TS SDKs draw a fresh salt and eph_sk per build, the proof holds no freshness.

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

// screen runs the policy over the opened slots under the rail and holds approval_required to the outflow's verdict.
func (p *screenedPolicy) screen(api frontend.API, rc frontend.Rangechecker, rail policy.Rail, sender frontend.Variable, slots []shared.Output) {
	// 1. Exempt is a bit, it switches assertExemption and the own pool lookups the thresholds read.
	api.AssertIsBoolean(p.Exempt)
	rail.Exempt = p.Exempt
	// 2. Screen returns zero while Outflow is off, so approval_required is set exactly when a limit row passes its co-sign bound.
	api.AssertIsEqual(p.ApprovalRequired, p.Screen(api, rc, rail, sender, slots))
}

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
