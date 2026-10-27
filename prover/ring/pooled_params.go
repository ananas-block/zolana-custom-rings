package ring

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

type PooledRecord struct {
	Member              Field  `json:"member"`
	Next                Field  `json:"next"`
	Lists               uint64 `json:"lists"`
	EscrowKey           Field  `json:"escrowKey"`
	MintPolicy          Field  `json:"mintPolicy"`
	WithdrawalThreshold Field  `json:"withdrawalThreshold"`
}

type PooledSubject struct {
	Member      Field  `json:"member"`
	RecordIndex uint32 `json:"recordIndex"`
}

type PooledEntry struct {
	Own     uint32   `json:"own"`
	Curator []uint32 `json:"curator"`
}

type SharedRegistryPath struct {
	Index    uint32    `json:"index"`
	Siblings [][]Field `json:"siblings"`
}

type SharedRegistryProof struct {
	Canopy []Field              `json:"canopy"`
	Paths  []SharedRegistryPath `json:"paths"`
}

type PooledPolicyParams struct {
	PolicyInputsParams
	OwnRecords         []PooledRecord      `json:"ownRecords"`
	CuratorRecords     []PooledRecord      `json:"curatorRecords"`
	OwnProof           SharedRegistryProof `json:"ownProof"`
	CuratorProof       SharedRegistryProof `json:"curatorProof"`
	OwnSubjects        []PooledSubject     `json:"ownSubjects"`
	CuratorSubjects    []PooledSubject     `json:"curatorSubjects"`
	SenderEntry        PooledEntry         `json:"senderEntry"`
	OwnerEntries       []PooledEntry       `json:"ownerEntries"`
	AssetEntries       []PooledEntry       `json:"assetEntries"`
	PublicAssetEntries []uint32            `json:"publicAssetEntries"`
}

type MemberPolicyV3Params struct {
	MemberPolicyInputsParams
	PooledPolicyParams
}

type DelegatePolicyV3Params struct {
	DelegatePolicyInputsParams
	PooledPolicyParams
}

type pooledParams interface {
	headed
	pooled() PooledPolicyParams
}

type pooledRequest[P pooledParams] struct {
	request[P]
	capacity policy.RecordPoolShape
}

func NewMemberPolicyV3Request(expected common.CircuitType, shape policy.MemberShapeV3) (common.ExtensionRequest, error) {
	c, err := policy.NewMemberPolicyCircuitV3(shape)
	if err != nil {
		return nil, err
	}
	build := func() (frontend.Circuit, error) { return policy.NewMemberPolicyCircuitV3(shape) }
	return newPooledRequest[MemberPolicyV3Params](expected, build, c.PolicyV3)
}

func NewDelegatePolicyV3Request(expected common.CircuitType, shape policy.DelegateShapeV3) (common.ExtensionRequest, error) {
	c, err := policy.NewDelegatePolicyCircuitV3(shape)
	if err != nil {
		return nil, err
	}
	build := func() (frontend.Circuit, error) { return policy.NewDelegatePolicyCircuitV3(shape) }
	return newPooledRequest[DelegatePolicyV3Params](expected, build, c.PolicyV3)
}

func newPooledRequest[P pooledParams](expected common.CircuitType, build func() (frontend.Circuit, error), shape policy.PolicyV3) (common.ExtensionRequest, error) {
	if expected == "" {
		return nil, fmt.Errorf("policy request circuit label is empty")
	}
	return &pooledRequest[P]{
		request:  request[P]{circuit: expected, build: build},
		capacity: policy.RecordPoolShape{Own: len(shape.OwnRecords), Curator: len(shape.CuratorRecords), OwnSubjects: len(shape.OwnSubjects), CuratorSubjects: len(shape.CuratorSubjects)},
	}, nil
}

func (r *pooledRequest[P]) Assignment() (frontend.Circuit, error) {
	if err := r.params.pooled().validateIndices(r.capacity); err != nil {
		return nil, err
	}
	return r.request.Assignment()
}

func (p PooledPolicyParams) pooled() PooledPolicyParams { return p }

func (p PooledPolicyParams) validateIndices(capacity policy.RecordPoolShape) error {
	if err := validatePoolIndices(p.OwnSubjects, p.OwnProof, capacity.Own); err != nil {
		return err
	}
	if err := validatePoolIndices(p.CuratorSubjects, p.CuratorProof, capacity.Curator); err != nil {
		return err
	}
	entries := append([]PooledEntry{p.SenderEntry}, p.OwnerEntries...)
	entries = append(entries, p.AssetEntries...)
	for _, entry := range entries {
		if err := entry.validateIndices(capacity); err != nil {
			return err
		}
	}
	for _, index := range p.PublicAssetEntries {
		if uint64(index) >= uint64(capacity.OwnSubjects) {
			return fmt.Errorf("policy public asset subject index is outside the pool")
		}
	}
	return nil
}

func validatePoolIndices(subjects []PooledSubject, proof SharedRegistryProof, records int) error {
	for _, subject := range subjects {
		if uint64(subject.RecordIndex) >= uint64(records) {
			return fmt.Errorf("policy record index is outside the pool")
		}
	}
	for _, path := range proof.Paths {
		if path.Index >= registry.Capacity {
			return fmt.Errorf("policy path index is outside the registry")
		}
	}
	return nil
}

func (e PooledEntry) validateIndices(capacity policy.RecordPoolShape) error {
	if uint64(e.Own) >= uint64(capacity.OwnSubjects) {
		return fmt.Errorf("policy own subject index is outside the pool")
	}
	for _, index := range e.Curator {
		if uint64(index) >= uint64(capacity.CuratorSubjects) {
			return fmt.Errorf("policy curator subject index is outside the pool")
		}
	}
	return nil
}
