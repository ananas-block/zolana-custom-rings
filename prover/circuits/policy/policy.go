// Package policy proves a custom ring's policy over a transaction SPP proves.
package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

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
