package policy_test

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"testing"
)

func TestPooledPolicyModes(t *testing.T) {
	worlds := []ringpolicy.World{ringpolicy.Confidential(), ringpolicy.Anonymous(), curated(), delegate2(), withdrawalWorld()}
	for i, world := range worlds {
		for _, own := range []bool{false, true} {
			if own && len(world.Table.Curator) != 0 {
				continue
			}
			world.OwnOnly = own
			t.Run(fmt.Sprintf("%d-own%v", i, own), func(t *testing.T) {
				b := world.Build(t).Pooled(t, policy.RecordPoolShape{})
				if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestPooledPolicyRetainsRefusals(t *testing.T) {
	for _, refusal := range refusals {
		if refusal.world == nil {
			continue
		}
		t.Run(refusal.name, func(t *testing.T) {
			w := refusal.honest()
			honest := w.Build(t).Pooled(t, policy.RecordPoolShape{})
			if err := test.IsSolved(honest.Assignment(), honest.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			refusal.world(&w)
			bad := w.Build(t).Pooled(t, policy.RecordPoolShape{})
			if test.IsSolved(bad.Assignment(), bad.Assignment(), ecc.BN254.ScalarField()) == nil {
				t.Fatal("refused policy solved")
			}
		})
	}
}

func TestPooledPolicyConstraintMatrix(t *testing.T) {
	for _, own := range []bool{false, true} {
		for _, shape := range []policy.MemberShape{{Outputs: 2}, {Outputs: 16, Withdrawals: 32}} {
			shape.OwnOnly = own
			for _, compact := range []bool{true, false} {
				capacity := policy.RecordPoolShape{}
				if compact {
					capacity.Own = 3
					if !own {
						capacity.Curator = 3
					}
				}
				c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: shape, Records: capacity})
				if err != nil {
					t.Fatal(err)
				}
				cs := ringkey.Compile(t, c)
				repeated := poolWorld(shape, false, false).Build(t).Pooled(t, capacity)
				requirePooledCompiledSolved(t, cs, repeated)
				if !compact {
					requirePooledCompiledSolved(t, cs, poolWorld(shape, true, false).Build(t).Pooled(t, capacity))
				}
				t.Logf("member-%d-w%d-own%v capacity=%d/%d constraints=%d", shape.Outputs, shape.Withdrawals, own, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
			}
		}
		for _, width := range []int{2, 4} {
			for _, compact := range []bool{true, false} {
				capacity := policy.RecordPoolShape{}
				if compact {
					capacity.Own = 3
					if !own {
						capacity.Curator = 3
					}
				}
				c, err := policy.NewDelegatePolicyCircuitV3(policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: transaction.Shape{NInputs: width, NOutputs: width}, OwnOnly: own}, Records: capacity})
				if err != nil {
					t.Fatal(err)
				}
				cs := ringkey.Compile(t, c)
				shape := policy.MemberShape{Outputs: width, OwnOnly: own}
				requirePooledCompiledSolved(t, cs, poolWorld(shape, false, true).Build(t).Pooled(t, capacity))
				if !compact {
					requirePooledCompiledSolved(t, cs, poolWorld(shape, true, true).Build(t).Pooled(t, capacity))
				}
				t.Logf("delegate-%dx%d-own%v capacity=%d/%d constraints=%d", width, width, own, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
			}
		}
	}
}

func requirePooledCompiledSolved(t *testing.T, cs constraint.ConstraintSystem, b ringpolicy.PooledWitness) {
	t.Helper()
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Fatal("pool must keep one private commitment")
	}
	witness, err := frontend.NewWitness(b.Assignment(), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err = cs.IsSolved(witness); err != nil {
		t.Fatal(err)
	}
}

func poolWorld(shape policy.MemberShape, distinct, delegate bool) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Outputs, w.WithdrawalCapacity, w.OwnOnly = shape.Outputs, shape.Withdrawals, shape.OwnOnly
	w.Table.Limits = nil
	w.Table.Rules = append(w.Table.Rules, ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit))
	w.Slots, w.Withdrawals = nil, nil
	w.Own = map[int64]ringpolicy.Record{ringpolicy.Sender: ringpolicy.Escrowed(ringregistry.AllowBit)}
	add := func(owner, asset int64) ringpolicy.Slot {
		w.Own[owner] = ringpolicy.Escrowed(ringregistry.AllowBit)
		w.Own[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		return ringpolicy.Slot{Owner: owner, Asset: asset, Amount: 1}
	}
	for i := range shape.Outputs + shape.Withdrawals {
		owner, asset := int64(ringpolicy.Alice), int64(ringpolicy.AssetA)
		if distinct {
			owner = int64(10000 + 2*i)
			asset = owner + 1
		}
		slot := add(owner, asset)
		if i < shape.Outputs {
			w.Slots = append(w.Slots, slot)
		} else {
			w.Withdrawals = append(w.Withdrawals, slot)
		}
	}
	if !delegate {
		for i := range transaction.NPublicSlots {
			asset := int64(ringpolicy.AssetA)
			if distinct {
				asset = int64(30000 + i)
			}
			w.Own[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}
			w.Public = append(w.Public, ringpolicy.PublicSlot{Asset: asset, Amount: -1})
		}
	} else {
		w.Outputs = 0
		w.Shape = transaction.Shape{NInputs: shape.Outputs, NOutputs: shape.Outputs}
		for range shape.Outputs {
			w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 1})
		}
	}
	if !shape.OwnOnly {
		w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
		for member, record := range w.Own {
			w.Curator[member] = record
		}
	}
	return w
}

func TestPooledPolicyBindsSubjectReferences(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*policy.PolicyV3)
	}{
		{"sender subject", func(p *policy.PolicyV3) { p.SenderEntry.Own = 1 }},
		{"owner subject", func(p *policy.PolicyV3) { p.OwnerEntries[1].Own = 0 }},
		{"asset subject", func(p *policy.PolicyV3) { p.AssetEntries[1].Own = 0 }},
		{"public subject", func(p *policy.PolicyV3) { p.PublicAssetEntries[0] = 0 }},
		{"withdrawal subject", func(p *policy.PolicyV3) { p.OwnerEntries[2].Own = 0 }},
		{"curator subject", func(p *policy.PolicyV3) { p.OwnerEntries[1].Curator[0] = 0 }},
		{"subject member", func(p *policy.PolicyV3) { p.OwnSubjects[1].Member = ringpolicy.Sender }},
		{"subject raw record", func(p *policy.PolicyV3) { p.OwnSubjects[1].RecordIndex = 0 }},
		{"subject index outside pool", func(p *policy.PolicyV3) { p.OwnerEntries[1].Own = 3 }},
		{"raw record index outside pool", func(p *policy.PolicyV3) { p.OwnSubjects[1].RecordIndex = 3 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := poolWorld(policy.MemberShape{Outputs: 2, Withdrawals: 1}, false, false)
			w.KeyEscrow = false
			b := w.Build(t).Pooled(t, policy.RecordPoolShape{Own: 3, Curator: 3})
			if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			tc.mutate(b.Policy())
			if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
				t.Fatal("forged subject reference solved")
			}
		})
	}
}

func TestPooledPolicyRejectsCapacityOverflow(t *testing.T) {
	for _, capacity := range []policy.RecordPoolShape{{Own: -1}, {Own: int(^uint(0) >> 1)}, {Curator: -1}, {Curator: int(^uint(0) >> 1)}, {OwnSubjects: -1}, {OwnSubjects: int(^uint(0) >> 1)}, {CuratorSubjects: -1}, {CuratorSubjects: int(^uint(0) >> 1)}} {
		if _, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2}, Records: capacity}); err == nil {
			t.Fatal("invalid capacity accepted")
		}
	}
}

func TestPooledPolicySharesAbsentPredecessor(t *testing.T) {
	w := poolWorld(policy.MemberShape{Outputs: 2}, true, false)
	w.KeyEscrow = false
	w.Own, w.Curator = map[int64]ringpolicy.Record{}, map[int64]ringpolicy.Record{}
	w.Table.Rules = []ringpolicy.Rule{ringpolicy.Forbid(policy.SubjectSender, ringregistry.FrozenBit), ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit), ringpolicy.Forbid(policy.SubjectAsset, ringregistry.BlockBit)}
	b := w.Build(t).Pooled(t, policy.RecordPoolShape{Own: 1, Curator: 1, OwnSubjects: 8, CuratorSubjects: 5})
	c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: policy.MemberShape{Outputs: 2}, Records: policy.RecordPoolShape{Own: 1, Curator: 1, OwnSubjects: 8, CuratorSubjects: 5}})
	if err != nil {
		t.Fatal(err)
	}
	cs := ringkey.Compile(t, c)
	requirePooledCompiledSolved(t, cs, b)
}

func TestPooledPolicyBindsVersion(t *testing.T) {
	old := ringpolicy.Confidential().Build(t)
	b := old.Pooled(t, policy.RecordPoolShape{})
	b.Member.PublicInputHash = old.Member.PublicInputHash
	if test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()) == nil {
		t.Fatal("v2 statement accepted by v3 circuit")
	}
}

func TestPooledPolicyDistinctWithdrawalCapacity(t *testing.T) {
	w := poolWorld(policy.MemberShape{Outputs: 2, Withdrawals: 2}, true, false)
	b := w.Build(t).Pooled(t, policy.RecordPoolShape{})
	if err := test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
