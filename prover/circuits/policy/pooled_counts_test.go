package policy_test

import (
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestDistinctParticipantSharedAssetCounts(t *testing.T) {
	for _, own := range []bool{false, true} {
		for _, shape := range []policy.MemberShape{{Outputs: 2}, {Outputs: 2, Withdrawals: 2}, {Outputs: 16, Withdrawals: 32}} {
			shape.OwnOnly = own
			for assets := 1; assets <= min(3, shape.Outputs+shape.Withdrawals); assets++ {
				w := distinctParticipantWorld(shape, assets, false)
				capacity := participantCapacity(shape, assets)
				c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: shape, Records: capacity})
				if err != nil {
					t.Fatal(err)
				}
				cs := ringkey.Compile(t, c)
				requirePooledCompiledSolved(t, cs, w.Build(t).Pooled(t, capacity))
				t.Logf("member-%d-w%d-own%v participants=%d assets=%d capacity=%d/%d constraints=%d", shape.Outputs, shape.Withdrawals, own, 1+shape.Outputs+shape.Withdrawals, assets, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
			}
		}
		for _, width := range []int{2, 4} {
			shape := policy.MemberShape{Outputs: width, OwnOnly: own}
			for assets := 1; assets <= min(3, width); assets++ {
				w := distinctParticipantWorld(shape, assets, false)
				w.Outputs = 0
				w.Shape = transaction.Shape{NInputs: width, NOutputs: width}
				for asset := range assets {
					var amount uint64
					for _, output := range w.Slots {
						if output.Asset == int64(30000+asset) {
							amount += output.Amount
						}
					}
					w.Inputs = append(w.Inputs, ringpolicy.Slot{Owner: ringpolicy.Sender, Asset: int64(30000 + asset), Amount: amount})
				}
				capacity := participantCapacity(shape, assets)
				c, err := policy.NewDelegatePolicyCircuitV3(policy.DelegateShapeV3{DelegateShape: policy.DelegateShape{Shape: w.Shape, OwnOnly: own}, Records: capacity})
				if err != nil {
					t.Fatal(err)
				}
				cs := ringkey.Compile(t, c)
				requirePooledCompiledSolved(t, cs, w.Build(t).Pooled(t, capacity))
				t.Logf("delegate-%dx%d-own%v participants=%d assets=%d capacity=%d/%d constraints=%d", width, width, own, 1+width, assets, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
			}
		}
		shape := policy.MemberShape{Outputs: 16, Withdrawals: 32, OwnOnly: own}
		w := distinctParticipantWorld(shape, 3, true)
		capacity := participantCapacity(shape, shape.Outputs+3)
		c, err := policy.NewMemberPolicyCircuitV3(policy.MemberShapeV3{MemberShape: shape, Records: capacity})
		if err != nil {
			t.Fatal(err)
		}
		cs := ringkey.Compile(t, c)
		requirePooledCompiledSolved(t, cs, w.Build(t).Pooled(t, capacity))
		t.Logf("member-%d-w%d-own%v participants=%d zero_output_assets=%d withdrawal_assets=3 capacity=%d/%d constraints=%d", shape.Outputs, shape.Withdrawals, own, 1+shape.Outputs+shape.Withdrawals, shape.Outputs, len(c.OwnRecords), len(c.CuratorRecords), cs.GetNbConstraints())
	}
}

func participantCapacity(shape policy.MemberShape, assets int) policy.RecordPoolShape {
	count := 1 + shape.Outputs + shape.Withdrawals + assets
	capacity := policy.RecordPoolShape{Own: count}
	if !shape.OwnOnly {
		capacity.Curator = count
	}
	return capacity
}

func distinctParticipantWorld(shape policy.MemberShape, assets int, zeroOutputAssets bool) ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Outputs, w.WithdrawalCapacity, w.OwnOnly = shape.Outputs, shape.Withdrawals, shape.OwnOnly
	w.Table.Limits = nil
	w.Table.Rules = append(w.Table.Rules, ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit))
	w.Own = map[int64]ringpolicy.Record{ringpolicy.Sender: ringpolicy.Escrowed(ringregistry.AllowBit)}
	w.Slots, w.Withdrawals, w.Public = nil, nil, nil
	totals := map[int64]int64{}
	for i := range shape.Outputs + shape.Withdrawals {
		owner, asset := int64(10000+i), int64(30000+i%assets)
		amount := uint64(1)
		if zeroOutputAssets && i < shape.Outputs {
			asset = int64(40000 + i)
			amount = 0
		}
		w.Own[owner] = ringpolicy.Escrowed(ringregistry.AllowBit)
		w.Own[asset] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		slot := ringpolicy.Slot{Owner: owner, Asset: asset, Amount: amount}
		if i < shape.Outputs {
			w.Slots = append(w.Slots, slot)
		} else {
			w.Withdrawals = append(w.Withdrawals, slot)
			totals[asset] += int64(amount)
		}
	}
	for i := range assets {
		asset := int64(30000 + i)
		if totals[asset] != 0 {
			w.Public = append(w.Public, ringpolicy.PublicSlot{Asset: asset, Amount: -totals[asset]})
		}
	}
	if !shape.OwnOnly {
		w.Table.Curator = map[uint64]bool{ringregistry.AllowBit: true}
		for member, record := range w.Own {
			w.Curator[member] = ringpolicy.Record{Lists: record.Lists}
		}
	}
	return w
}
