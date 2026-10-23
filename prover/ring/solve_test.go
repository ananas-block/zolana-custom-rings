package ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const (
	packedKey    common.CircuitType = "custom-ring-audit-packed-2"
	deliveredKey common.CircuitType = "custom-ring-audit-delivered-8"
	anonymousKey common.CircuitType = "custom-ring-audit-anonymous-4-2"
	entryKey     common.CircuitType = "custom-ring-audit-anonymous-entry-8-2"
	memberKey    common.CircuitType = "custom-ring-policy-member-2"
	delegateKey  common.CircuitType = "custom-ring-policy-delegate-2x2"
	applyKey     common.CircuitType = "custom-ring-apply-records-1"
	batchKey     common.CircuitType = "custom-ring-apply-records-16"
)

// hostRequests covers one shape per family with a ringtest twin.
var hostRequests = map[common.CircuitType]func(t testing.TB) any{
	packedKey: func(t testing.TB) any {
		return requestOf[PackedAuditParams](t, packedKey, ringaudit.PackedAuditOf(t, 2, 2).Circuit(t))
	},
	deliveredKey: func(t testing.TB) any {
		return requestOf[DeliveredAuditParams](t, deliveredKey, ringaudit.NewDeliveredAudit(t, 8).Circuit(t))
	},
	anonymousKey: func(t testing.TB) any {
		shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
		return requestOf[AnonymousAuditParams](t, anonymousKey, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
	},
	entryKey: func(t testing.TB) any {
		shape := audit.AnonymousAuditShape{InputClass: 8, Outputs: 2, FullOpenings: true}
		return requestOf[AnonymousAuditParams](t, entryKey, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
	},
	memberKey: func(t testing.TB) any {
		return requestOf[MemberPolicyParams](t, memberKey, ringpolicy.Confidential().Build(t).Assignment())
	},
	delegateKey: func(t testing.TB) any {
		world := ringpolicy.Delegate(transaction.Shape{NInputs: 2, NOutputs: 2})
		return requestOf[DelegatePolicyParams](t, delegateKey, world.Build(t).Assignment())
	},
	applyKey: func(t testing.TB) any { return applyRequest(t, applyKey, 1) },
	batchKey: func(t testing.TB) any { return applyRequest(t, batchKey, 16) },
}

func TestHostRequestsDecodeAndSolve(t *testing.T) {
	for circuit, request := range hostRequests {
		t.Run(string(circuit), func(t *testing.T) {
			t.Parallel()
			payload := mustMarshal(t, request(t))
			circuitOf := extensionOf(t, circuit).Circuit
			if err := test.IsSolved(circuitOf(), decodePayload(t, circuit, payload), ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			var raw map[string]any
			if err := json.Unmarshal(payload, &raw); err != nil {
				t.Fatal(err)
			}
			raw["publicInputHash"] = fi(1)
			if test.IsSolved(circuitOf(), decodePayload(t, circuit, mustMarshal(t, raw)), ecc.BN254.ScalarField()) == nil {
				t.Fatal("another public input solved")
			}
		})
	}
}

// applyRequest inserts members up to the key's capacity, a full batch then rewrites one of them and skips an empty record.
func applyRequest(t testing.TB, circuit common.CircuitType, capacity int) *ApplyRecordsParams {
	t.Helper()
	entry := func(member, mask, escrow int64) ringregistry.Entry {
		return ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(mask), EscrowKey: big.NewInt(escrow)}
	}
	entries := []ringregistry.Entry{entry(0x100, ringregistry.AllowBit, 0)}
	if capacity > 1 {
		entries = nil
		for i := range capacity - 2 {
			entries = append(entries, entry(int64(0x100+i), ringregistry.AllowBit, 0))
		}
		empty := ringregistry.Entry{Member: big.NewInt(0x200), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(0), EscrowKey: big.NewInt(0)}
		entries = append(entries, entry(0x100, ringregistry.EscrowBit, 0xe0), empty)
	}
	members := ringregistry.New(t)
	// A nonzero chain checkpoint, as a queue past its first batch carries.
	p := &ApplyRecordsParams{
		RequestHead: RequestHead{CircuitType: circuit}, OldRoot: fb(members.Root()), OldNextIndex: uint32(members.NextIndex()),
		ChainStart: fi(0x5eed), Count: uint8(len(entries)), Writes: make([]*RecordWrite, capacity),
	}
	chain := p.ChainStart.Int
	for i, e := range entries {
		w := members.Apply(t, e)
		hash := ringtest.MustPoseidonHash(t, big.NewInt(shared.QueueWriteDomain), e.Member, e.Mask, e.Value, e.EscrowKey)
		chain = ringtest.MustPoseidonHash(t, chain, hash)
		p.Writes[i] = &RecordWrite{
			Entry:  QueueEntry{Member: fb(e.Member), Mask: e.Mask.Uint64(), Value: e.Value.Uint64(), EscrowKey: fb(e.EscrowKey)},
			Exists: w.Exists, OldNext: fb(w.OldNext), OldLists: w.OldLists.Uint64(), OldEscrow: fb(w.OldEscrow),
			Index: w.Slot.Index, Path: flatPath(w.Slot),
			LowMember: fb(w.Low.Member), LowNext: fb(w.Low.Next), LowLists: w.Low.Lists.Uint64(), LowEscrow: fb(w.Low.EscrowKey),
			LowIndex: w.LowPath.Index, LowPath: flatPath(w.LowPath),
		}
	}
	p.NewRoot, p.NewNextIndex, p.ChainEnd = fb(members.Root()), uint32(members.NextIndex()), fb(chain)
	p.PublicInputHash = fb(spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(shared.ApplyRecordsDomain), p.OldRoot.Int, p.NewRoot.Int, big.NewInt(int64(p.OldNextIndex)),
		big.NewInt(int64(p.NewNextIndex)), p.ChainStart.Int, p.ChainEnd.Int, big.NewInt(int64(p.Count)),
	}))
	return p
}

func flatPath(path ringregistry.Path) []Field {
	var flat []Field
	for _, row := range path.Siblings {
		for _, sibling := range row {
			flat = append(flat, fb(sibling))
		}
	}
	return flat
}

func fi(v int64) Field    { return Field{big.NewInt(v)} }
func fb(v *big.Int) Field { return Field{new(big.Int).Set(v)} }
