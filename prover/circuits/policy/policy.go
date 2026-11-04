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
	OwnOnly bool `gnark:"-"`
	// Senders counts the owners the key screens, Outputs the slots, the pool holds a row for each.
	Senders, Outputs int `gnark:"-"`
	// SaltedKeys widens each pool past its public subjects.
	SaltedKeys      int `gnark:"-"`
	WithdrawalCount frontend.Variable
	WithdrawalHash  frontend.Variable
	Withdrawals     []WithdrawalWires
	PolicyHash      frontend.Variable
	RingProgramID   frontend.Variable
	OwnRoot         frontend.Variable
	CuratorRoot     frontend.Variable
	PublicAssets    [transaction.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, the statement alone reads them.
	PublicAmounts [transaction.NPublicSlots]frontend.Variable
	// PublicGross are the gross withdrawals per slot, no deposit subtracted, read while Outflow is on.
	PublicGross [transaction.NPublicSlots]frontend.Variable
	Table
}

type Policy struct {
	PolicyInputs
	OwnRecords         []registry.Record
	CuratorRecords     []registry.Record
	OwnProof           registry.SharedQuadProof
	CuratorProof       registry.SharedQuadProof
	OwnSubjects        []PoolSubject
	CuratorSubjects    []PoolSubject
	SenderEntries      []OwnerEntry
	OwnerEntries       []OwnerEntry
	AssetEntries       []PoolEntry
	PublicAssetEntries []frontend.Variable
}

type InputsShape struct {
	Outputs, Withdrawals, Senders, SaltedKeys int
	OwnOnly                                   bool
}

func (s InputsShape) Inputs() PolicyInputs {
	return PolicyInputs{OwnOnly: s.OwnOnly, Senders: s.Senders, Outputs: s.Outputs, SaltedKeys: s.SaltedKeys, Withdrawals: make([]WithdrawalWires, s.Withdrawals)}
}

// NewPolicy sizes the record pools, capacity zero fields take the shape's limits.
func NewPolicy(inputs PolicyInputs, capacity RecordPoolShape, publicAssets int) (Policy, error) {
	payments := inputs.Outputs + len(inputs.Withdrawals)
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
		SenderEntries:      make([]OwnerEntry, inputs.Senders),
		OwnerEntries:       make([]OwnerEntry, payments),
		AssetEntries:       make([]PoolEntry, payments),
		PublicAssetEntries: make([]frontend.Variable, publicAssets),
	}
	for i := range p.SenderEntries {
		p.SenderEntries[i] = newOwnerEntry(inputs.OwnOnly)
	}
	for i := range p.OwnerEntries {
		p.OwnerEntries[i], p.AssetEntries[i] = newOwnerEntry(inputs.OwnOnly), newPoolEntry(inputs.OwnOnly)
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
	payments := p.Outputs + len(p.Withdrawals)
	if p.Outputs == 0 || len(p.OwnerEntries) != payments || len(p.AssetEntries) != payments {
		return fmt.Errorf("policy requires owner and asset references for every payment")
	}
	if p.Senders == 0 || len(p.SenderEntries) != p.Senders {
		return fmt.Errorf("policy requires one reference per screened sender")
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
	for _, entry := range slices.Concat(p.SenderEntries, p.OwnerEntries) {
		if err := entry.validate(p.OwnOnly); err != nil {
			return err
		}
	}
	for _, entry := range p.AssetEntries {
		if err := entry.validate(p.OwnOnly); err != nil {
			return err
		}
	}
	return nil
}
