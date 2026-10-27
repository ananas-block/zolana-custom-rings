package ringpolicy

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type PooledWitness struct {
	Member   *policy.MemberPolicyCircuitV3
	Delegate *policy.DelegatePolicyCircuitV3
}

type recordCollector struct {
	records        []circuitregistry.Record
	leafIndices    []uint64
	indices        map[string]int
	subjects       []policy.PoolSubject
	subjectIndices map[string]int
}

func (b Witness) Pooled(t testing.TB, capacity policy.RecordPoolShape) PooledWitness {
	t.Helper()
	old := b.Policy()
	var pooled PooledWitness
	if b.Member != nil {
		c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: len(old.Outputs), Withdrawals: len(old.Withdrawals), OwnOnly: old.OwnOnly}, Records: capacity})
		if err != nil {
			t.Fatal(err)
		}
		c.MemberPolicyValues = b.Member.MemberPolicyValues
		pooled.Member = c
	} else {
		c, err := policy.NewDelegatePolicyCircuitV3(policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: transaction.Shape{NInputs: len(b.Delegate.Inputs), NOutputs: len(old.Outputs)}, OwnOnly: old.OwnOnly}, Records: capacity})
		if err != nil {
			t.Fatal(err)
		}
		c.DelegatePolicyValues = b.Delegate.DelegatePolicyValues
		pooled.Delegate = c
	}
	p := pooled.Policy()
	p.PolicyInputs = old.PolicyInputs
	own, curator := recordCollector{indices: map[string]int{}, subjectIndices: map[string]int{}}, recordCollector{indices: map[string]int{}, subjectIndices: map[string]int{}}
	foreign := false
	for _, source := range p.Sources {
		foreign = foreign || ringtest.AsBigInt(source.Registry).Sign() != 0
	}
	entry := func(member frontend.Variable, active bool, opening policy.Entry) policy.PoolEntry {
		e := policy.PoolEntry{Own: own.add(member, active, opening.Own)}
		if !p.OwnOnly {
			e.Curator = []frontend.Variable{curator.add(member, active && foreign, opening.Curator[0])}
		}
		return e
	}
	p.SenderEntry = entry(old.SenderPkHash, true, old.SenderEntry)
	for i, out := range p.Outputs {
		active := ringtest.AsBigInt(out.Domain).Int64() == transaction.UtxoDomain
		p.OwnerEntries[i] = entry(out.OwnerPkHash, active, old.OwnerEntries[i])
		p.AssetEntries[i] = entry(out.Asset, active, old.AssetEntries[i])
	}
	for i, out := range p.Withdrawals {
		active := int64(i) < ringtest.AsBigInt(p.WithdrawalCount).Int64()
		index := len(p.Outputs) + i
		p.OwnerEntries[index] = entry(out.Owner, active, old.OwnerEntries[index])
		p.AssetEntries[index] = entry(out.Asset, active, old.AssetEntries[index])
	}
	for i, asset := range p.PublicAssets {
		p.PublicAssetEntries[i] = own.add(asset, b.Member != nil && ringtest.AsBigInt(asset).Sign() != 0, old.PublicAssetEntries[i])
	}
	if len(curator.records) == 0 && !p.OwnOnly {
		curator.add(old.SenderPkHash, true, old.SenderEntry.Curator[0])
	}
	p.OwnProof = own.fill(t, p.OwnRecords, p.OwnSubjects, b.ownRegistry)
	if !p.OwnOnly {
		p.CuratorProof = curator.fill(t, p.CuratorRecords, p.CuratorSubjects, b.curatorRegistry)
	}
	pooled.Rebind(t)
	return pooled
}

func (b PooledWitness) Policy() *policy.PolicyV3 {
	if b.Member != nil {
		return &b.Member.PolicyV3
	}
	return &b.Delegate.PolicyV3
}

func (b PooledWitness) Assignment() frontend.Circuit {
	if b.Member != nil {
		return b.Member
	}
	return b.Delegate
}

func (b PooledWitness) Rebind(t testing.TB) {
	t.Helper()
	if b.Member != nil {
		b.Member.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(b.Member.Statement()))
	} else {
		b.Delegate.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(b.Delegate.Statement()))
	}
}

func (c *recordCollector) add(member frontend.Variable, active bool, opening circuitregistry.QuadOpening) int {
	if !active {
		return 0
	}
	subjectKey := ringtest.AsBigInt(member).String()
	if index, ok := c.subjectIndices[subjectKey]; ok {
		return index
	}
	key := ringtest.AsBigInt(opening.Path.Index).String()
	recordIndex, ok := c.indices[key]
	if !ok {
		record := circuitregistry.Record{Member: member, Next: opening.Next, Lists: opening.Lists, EscrowKey: opening.EscrowKey, MintPolicy: opening.MintPolicy, WithdrawalThreshold: opening.WithdrawalThreshold}
		if ringtest.AsBigInt(opening.Present).Sign() == 0 {
			record = circuitregistry.Record{Member: opening.LowMember, Next: opening.LowNext, Lists: opening.LowLists, EscrowKey: opening.LowEscrow, MintPolicy: opening.LowMintPolicy, WithdrawalThreshold: opening.LowWithdrawalThreshold}
		}
		recordIndex = len(c.records)
		c.indices[key] = recordIndex
		c.records = append(c.records, record)
		c.leafIndices = append(c.leafIndices, ringtest.AsBigInt(opening.Path.Index).Uint64())
	}
	index := len(c.subjects)
	c.subjectIndices[subjectKey] = index
	c.subjects = append(c.subjects, policy.PoolSubject{Member: member, RecordIndex: recordIndex})
	return index
}

func (c recordCollector) fill(t testing.TB, target []circuitregistry.Record, subjects []policy.PoolSubject, tree *ringregistry.Registry) circuitregistry.SharedQuadProof {
	t.Helper()
	if len(c.records) > len(target) {
		t.Fatalf("pool needs %d records with capacity %d", len(c.records), len(target))
	}
	if len(c.subjects) > len(subjects) {
		t.Fatalf("pool needs %d subjects with capacity %d", len(c.subjects), len(subjects))
	}
	for i := range subjects {
		subjects[i] = c.subjects[i%len(c.subjects)]
	}
	indices := make([]uint64, len(target))
	for i := range target {
		target[i] = c.records[i%len(c.records)]
		indices[i] = c.leafIndices[i%len(c.leafIndices)]
	}
	proof, err := tree.SharedProof(indices)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}
