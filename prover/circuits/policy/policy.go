// Package policy proves a custom ring's policy over a transaction SPP proves.
package policy

import (
	"fmt"
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type PolicyInputs struct {
	OwnOnly bool `gnark:"-"`
	// Senders counts the owners the key screens, Outputs the slots, the pool holds a row for each, Private the private rows.
	Senders, Outputs, Private int `gnark:"-"`
	WithdrawalCount           frontend.Variable
	WithdrawalHash            frontend.Variable
	Withdrawals               []WithdrawalWires
	PolicyHash                frontend.Variable
	RingProgramID             frontend.Variable
	OwnRoot                   frontend.Variable
	CuratorRoot               frontend.Variable
	// PrivateRoot is the private list tree the source names, zero without one.
	PrivateRoot  frontend.Variable
	PublicAssets [transaction.NPublicSlots]frontend.Variable
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
	SenderEntries      []PoolEntry
	OwnerEntries       []PoolEntry
	AssetEntries       []PoolEntry
	PublicAssetEntries []frontend.Variable
	PrivateRows        []privatelist.Row
	// PrivateOwners are the rows' subjects, PrivateTracking their tracking subjects.
	PrivateOwners   []frontend.Variable
	PrivateTracking []frontend.Variable
}

type InputsShape struct {
	Outputs, Withdrawals, Senders, Private int
	OwnOnly                                bool
}

func (s InputsShape) Inputs() PolicyInputs {
	return PolicyInputs{OwnOnly: s.OwnOnly, Senders: s.Senders, Outputs: s.Outputs, Private: s.Private, Withdrawals: make([]WithdrawalWires, s.Withdrawals)}
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
		SenderEntries:      make([]PoolEntry, inputs.Senders),
		OwnerEntries:       make([]PoolEntry, payments),
		AssetEntries:       make([]PoolEntry, payments),
		PublicAssetEntries: make([]frontend.Variable, publicAssets),
		PrivateRows:        make([]privatelist.Row, inputs.Private),
		PrivateOwners:      make([]frontend.Variable, inputs.Private),
		PrivateTracking:    make([]frontend.Variable, inputs.Private),
	}
	private := inputs.Private > 0
	for i := range p.SenderEntries {
		p.SenderEntries[i] = newPoolEntry(inputs.OwnOnly, private)
	}
	for i := range p.OwnerEntries {
		p.OwnerEntries[i], p.AssetEntries[i] = newPoolEntry(inputs.OwnOnly, private), newPoolEntry(inputs.OwnOnly, false)
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
	private := p.Private > 0
	for _, entry := range slices.Concat(p.SenderEntries, p.OwnerEntries) {
		if err := entry.validate(p.OwnOnly, private); err != nil {
			return err
		}
	}
	for _, entry := range p.AssetEntries {
		if err := entry.validate(p.OwnOnly, false); err != nil {
			return err
		}
	}
	if len(p.PrivateRows) != p.Private || len(p.PrivateOwners) != p.Private || len(p.PrivateTracking) != p.Private {
		return fmt.Errorf("policy requires one owner and tracking reference per private row")
	}
	return nil
}
