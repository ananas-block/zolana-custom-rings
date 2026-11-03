// Holds the statement values the policy section reads from the program. Every
// value a rule reads ties back to the statement, so the proof checks the
// transfer the program settles.
//
// Read after policy/table.go, policy/record_pool.go. Read before
// policy/transaction.go, policy/screen.go.

// Package policy proves a custom ring's policy over a transaction SPP proves.
package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Local constraints, Screen asserts them:
// 1. While screened the table hashes to policy_hash and every enabled rule holds for the sender and for every live payment's owner and asset on the lists their records carry, unless an amount guard exempts it.
// 2. Each recipient is its slot's owner identity while screened and published, zero otherwise.
// 3. withdrawal_hash reopens over the live legs, a live leg a nonzero amount of a nonzero asset, every amount below 2^64.
// 4. While Outflow is on every limit row's outflow is never negative and within its cap, and the approval is set exactly when one passes its co-sign bound.
// 5. Under key escrow every UTXO output's owner record escrows the output's nullifier key.
// 6. Under exempt every public slot's gross withdrawal lies at or under its asset record's threshold, zero off a record.
// 7. Every record a gate queries opens under own_root, under curator_root when its list is foreign.
//
// Program-derived facts, the statement fixes them:
// 8. policy_hash is the ring account's written table hash, zero on an audit-only ring.
// 9. own_root and curator_root are the registry roots at the frame's revisions, zero where no pool is active.
// 10. Each public slot's asset, net and gross come from the program's fold of the settled legs, a deposit never lowers a gross.
// 11. The recipients are the frame's identities on a confidential rail under a policy, zero otherwise.
// 12. The gates come from the rail, the instruction tag, the frame flags and policy_hash.
// 13. The statement's sender is the sole owner signer under a policy on the signer rail, the framed owner key on the in-proof rail, zero on the authority rail, absent on the anonymous family.
//
// Guarantees the section leans on:
// 14. SPP authorizes the owner signer over every spent input, the signer rail's sender owns the inputs with no ring constraint.
// 15. The transfer circuit passes the statement's sender on the signer and in-proof rails and a private member it holds every opened input to on the authority and anonymous rails.
// 16. SPP settles exactly the outputs under private_tx_hash, the transfer circuit reopens the hash over the slots the policy screens.

type PolicyInputs struct {
	OwnOnly         bool `gnark:"-"`
	WithdrawalCount frontend.Variable
	WithdrawalHash  frontend.Variable
	Withdrawals     []WithdrawalWires
	PolicyHash      frontend.Variable
	RingProgramID   frontend.Variable
	OwnRoot         frontend.Variable
	CuratorRoot     frontend.Variable
	PublicAssets    [transaction.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, a withdrawal enters as the field negation of its amount.
	PublicAmounts [transaction.NPublicSlots]frontend.Variable
	// PublicGross are the gross withdrawals per slot, read under an exemption.
	PublicGross [transaction.NPublicSlots]frontend.Variable
	Table

	// CtHashes are each output owner's escrowed key ciphertext hashes, read only under key escrow.
	CtHashes   []frontend.Variable
	Recipients []frontend.Variable
}

type Policy struct {
	PolicyInputs
	OwnRecords         []registry.Record
	CuratorRecords     []registry.Record
	OwnProof           registry.SharedQuadProof
	CuratorProof       registry.SharedQuadProof
	OwnSubjects        []PoolSubject
	CuratorSubjects    []PoolSubject
	SenderEntry        PoolEntry
	OwnerEntries       []PoolEntry
	AssetEntries       []PoolEntry
	PublicAssetEntries []frontend.Variable
}

// NewPolicyInputs sizes the statement wires of a policy over outputs output slots and withdrawals legs.
func NewPolicyInputs(outputs, withdrawals int, ownOnly bool) PolicyInputs {
	return PolicyInputs{OwnOnly: ownOnly, CtHashes: make([]frontend.Variable, outputs), Recipients: make([]frontend.Variable, outputs), Withdrawals: make([]WithdrawalWires, withdrawals)}
}

// NewPolicy sizes the record pools, capacity zero fields take the shape's limits.
func NewPolicy(inputs PolicyInputs, capacity RecordPoolShape, publicAssets int) (Policy, error) {
	payments := len(inputs.CtHashes) + len(inputs.Withdrawals)
	limits := inputs.recordCapacity(publicAssets)
	capacity = capacity.withDefaults(limits)
	if err := capacity.validate(limits); err != nil {
		return Policy{}, err
	}
	p := Policy{
		PolicyInputs:       inputs,
		OwnRecords:         make([]registry.Record, capacity.Own),
		CuratorRecords:     make([]registry.Record, capacity.Curator),
		OwnSubjects:        make([]PoolSubject, capacity.OwnSubjects),
		CuratorSubjects:    make([]PoolSubject, capacity.CuratorSubjects),
		SenderEntry:        newPoolEntry(inputs.OwnOnly),
		OwnerEntries:       make([]PoolEntry, payments),
		AssetEntries:       make([]PoolEntry, payments),
		PublicAssetEntries: make([]frontend.Variable, publicAssets),
	}
	for i := range p.OwnerEntries {
		p.OwnerEntries[i], p.AssetEntries[i] = newPoolEntry(inputs.OwnOnly), newPoolEntry(inputs.OwnOnly)
	}
	var err error
	if p.OwnProof, err = registry.NewSharedQuadProof(capacity.Own); err != nil {
		return Policy{}, err
	}
	if !inputs.OwnOnly {
		if p.CuratorProof, err = registry.NewSharedQuadProof(capacity.Curator); err != nil {
			return Policy{}, err
		}
	}
	return p, nil
}

func (p *Policy) RecordPools() RecordPoolShape {
	return RecordPoolShape{Own: len(p.OwnRecords), Curator: len(p.CuratorRecords), OwnSubjects: len(p.OwnSubjects), CuratorSubjects: len(p.CuratorSubjects)}
}

// Validate refuses a pool or reference list sized off the key's shape before any wire is read.
func (p *Policy) Validate(publicAssets int) error {
	payments := len(p.CtHashes) + len(p.Withdrawals)
	if len(p.CtHashes) == 0 || len(p.OwnerEntries) != payments || len(p.AssetEntries) != payments {
		return fmt.Errorf("policy requires owner and asset references for every payment")
	}
	if len(p.Recipients) != len(p.CtHashes) {
		return fmt.Errorf("policy requires one recipient per output")
	}
	if len(p.PublicAssetEntries) != publicAssets {
		return fmt.Errorf("policy requires one public asset reference per public slot")
	}
	if err := p.RecordPools().validate(p.recordCapacity(publicAssets)); err != nil {
		return err
	}
	if err := p.OwnProof.Validate(len(p.OwnRecords)); err != nil {
		return err
	}
	if !p.OwnOnly {
		if err := p.CuratorProof.Validate(len(p.CuratorRecords)); err != nil {
			return err
		}
	}
	for _, entry := range slices.Concat([]PoolEntry{p.SenderEntry}, p.OwnerEntries, p.AssetEntries) {
		if err := entry.validate(p.OwnOnly); err != nil {
			return err
		}
	}
	return nil
}
