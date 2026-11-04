package ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringdeposit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const (
	transferKey   common.CircuitType = "custom-ring-transfer-2-in24-w4-s4"
	transfer4Key  common.CircuitType = "custom-ring-transfer-4-in24-w4-s4"
	transfer8Key  common.CircuitType = "custom-ring-transfer-8-in16-w4-s4"
	transfer16Key common.CircuitType = "custom-ring-transfer-16-in5-w8-s5"
	wideKey       common.CircuitType = "custom-ring-transfer-8-in24-w32-s24"
	entryKey      common.CircuitType = "custom-ring-transfer-entry-4-in8-w4-s8"
	entry8Key     common.CircuitType = "custom-ring-transfer-entry-8-in2-w4-s2"
	applyKey      common.CircuitType = "custom-ring-apply-records-1"
	batchKey      common.CircuitType = "custom-ring-apply-records-16"
	enrollKey     common.CircuitType = "custom-ring-apply-enrollments-2"
	registerKey   common.CircuitType = "custom-ring-register-key"
	depositKey    common.CircuitType = "custom-ring-deposit-8"
	mergeKey      common.CircuitType = "custom-ring-merge-v4"
)

func TestHostRequestsDecodeAndSolve(t *testing.T) {
	for _, circuit := range []common.CircuitType{transferKey, transfer4Key, transfer8Key, transfer16Key, wideKey, entryKey, entry8Key, applyKey, batchKey, enrollKey, registerKey, depositKey, mergeKey} {
		t.Run(string(circuit), func(t *testing.T) {
			payload := mustMarshal(t, hostRequest(t, keyOf(t, circuit)))
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

func hostRequest(t testing.TB, k Key) any {
	t.Helper()
	switch k.Family {
	case Transfer:
		w := ringtransfer.Signed(k.transferShape())
		w.Withdrawals, w.Public = fixtureLeg(t)
		w.DefaultInput = k.Entry
		return requestOf[TransferParams](t, k.Circuit, w.Build(t).Circuit)
	case ApplyRecords:
		return applyRequest(t, k.Circuit, k.Inputs)
	case ApplyEnrollments:
		return enrollmentsRequest(t, k.Circuit, k.Inputs)
	case RegisterKey:
		return registerKeyRequest(t, k.Circuit, big.NewInt(0x0b))
	case Deposit:
		return requestOf[DepositParams](t, k.Circuit, ringdeposit.BuildScreened(t, k.Inputs, ringdeposit.Allowlisted(ringdeposit.MintA)).Narrow(t, k.Inputs).Circuit)
	case Merge:
		return requestOf[MergeParams](t, k.Circuit, ringmerge.Build(t).Circuit)
	}
	t.Fatalf("no host request for ring family %d", k.Family)
	return nil
}

// fixtureLeg withdraws one leg of the fixture asset, so every transfer request carries a withdrawal.
func fixtureLeg(t testing.TB) ([]ringtransfer.Withdrawal, []ringtransfer.PublicSlot) {
	t.Helper()
	asset := ringtransfer.Asset(t)
	return []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: asset, Amount: 10}}, []ringtransfer.PublicSlot{{Asset: asset, Net: -10, Gross: 10}}
}

func keyOf(t testing.TB, circuit common.CircuitType) Key {
	t.Helper()
	for _, key := range Keys {
		if key.Circuit == circuit {
			return key
		}
	}
	t.Fatalf("%s is no catalog key", circuit)
	return Key{}
}

// applyRequest inserts members up to the key's capacity, a full batch then rewrites one of them and skips an empty record.
func applyRequest(t testing.TB, circuit common.CircuitType, capacity int) *ApplyRecordsParams {
	t.Helper()
	entry := func(member, mask int64) ringregistry.Entry {
		return ringregistry.Entry{Member: big.NewInt(member), Mask: big.NewInt(mask), Value: big.NewInt(mask)}
	}
	entries := []ringregistry.Entry{entry(0x100, ringregistry.AllowBit)}
	if capacity > 1 {
		entries = nil
		for i := range capacity - 2 {
			entries = append(entries, entry(int64(0x100+i), ringregistry.AllowBit))
		}
		empty := ringregistry.Entry{Member: big.NewInt(0x200), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(0)}
		entries = append(entries, entry(0x100, ringregistry.BlockBit), empty)
	}
	// A nonzero chain checkpoint, as a queue past its first batch carries.
	return (registryBatch{circuit, capacity, ringregistry.New(t), entries, big.NewInt(0x5eed)}).request(t)
}

type registryBatch struct {
	circuit    common.CircuitType
	capacity   int
	members    *ringregistry.Registry
	entries    []ringregistry.Entry
	chainStart *big.Int
}

func (batch registryBatch) request(t testing.TB) *ApplyRecordsParams {
	t.Helper()
	members, entries := batch.members, batch.entries
	p := &ApplyRecordsParams{
		RequestHead: RequestHead{CircuitType: batch.circuit}, OldRoot: fb(members.Root()), OldNextIndex: uint32(members.NextIndex()),
		ChainStart: fb(batch.chainStart), Count: uint8(len(entries)), Writes: make([]*RecordWrite, batch.capacity),
	}
	chain := p.ChainStart.Int
	for i, e := range entries {
		w := members.Apply(t, e)
		chain = ringtest.MustPoseidonHash(t, chain, e.Hash(t))
		p.Writes[i] = &RecordWrite{
			Entry:  QueueEntry{Member: fb(e.Member), Mask: e.Mask.Uint64(), Value: e.Value.Uint64(), MintPolicy: fz(e.MintPolicy), WithdrawalThreshold: fz(e.WithdrawalThreshold), AssetLimits: limitFields(e.AssetLimits)},
			Exists: w.Exists, OldNext: fb(w.OldNext), OldLists: w.OldLists.Uint64(), OldMintPolicy: fz(w.OldMintPolicy), OldWithdrawalThreshold: fz(w.OldWithdrawalThreshold), OldAssetLimits: limitFields(w.OldAssetLimits),
			Index: w.Slot.Index, Path: flatPath(w.Slot),
			LowMember: fb(w.Low.Member), LowNext: fb(w.Low.Next), LowLists: w.Low.Lists.Uint64(), LowMintPolicy: fz(w.Low.MintPolicy), LowWithdrawalThreshold: fz(w.Low.WithdrawalThreshold), LowAssetLimits: limitFields(w.Low.AssetLimits),
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

// enrollmentsRequest inserts one owner per slot and rotates the last in a batch wider than one.
func enrollmentsRequest(t testing.TB, circuit common.CircuitType, capacity int) *ApplyEnrollmentsParams {
	t.Helper()
	tree := ringregistry.NewTracking(t)
	entry := func(i int, revision int64) ringregistry.TrackingEntry {
		owner := big.NewInt(0x100 + int64(i))
		return ringregistry.TrackingEntry{Member: owner, NullifierPk: spptest.MustNullifierPk(t, owner), CtHash: big.NewInt(0xc0), View0: big.NewInt(revision), View1: big.NewInt(1), Revision: big.NewInt(revision), ListTag: big.NewInt(0xd0)}
	}
	assignment, err := registry.NewApplyEnrollmentsCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	assignment.OldRoot, assignment.OldNextIndex, assignment.ChainStart = tree.Root(), tree.NextIndex(), big.NewInt(0x5eed)
	chain := big.NewInt(0x5eed)
	for i := range assignment.Writes {
		e := entry(i, 1)
		if capacity > 1 && i == capacity-1 {
			e = entry(0, 2)
		}
		assignment.Writes[i] = tree.Apply(t, e).Wires()
		chain = ringtest.MustPoseidonHash(t, chain, e.Hash(t))
	}
	assignment.NewRoot, assignment.NewNextIndex, assignment.ChainEnd, assignment.Count = tree.Root(), tree.NextIndex(), chain, capacity
	assignment.PublicInputHash = spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(shared.ApplyEnrollmentsDomain), ringtest.AsBigInt(assignment.OldRoot), ringtest.AsBigInt(assignment.NewRoot),
		ringtest.AsBigInt(assignment.OldNextIndex), ringtest.AsBigInt(assignment.NewNextIndex), ringtest.AsBigInt(assignment.ChainStart), chain, big.NewInt(int64(capacity)),
	})
	return requestOf[ApplyEnrollmentsParams](t, circuit, assignment)
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

func registerKeyRequest(t testing.TB, circuit common.CircuitType, member *big.Int) *RegisterKeyParams {
	t.Helper()
	keys := ringaudit.DefaultKeys(t)
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	sealed := keys.SealStream(t, secret[:], shared.NfKeyEncInfo)
	secretField := new(big.Int).SetBytes(secret[1:])
	nullifierPk := spptest.MustNullifierPk(t, secretField)
	listTag := ringregistry.ListTag(t, ringregistry.ListSalt(t, secretField))
	ringID := big.NewInt(0x7711)
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	return &RegisterKeyParams{
		RequestHead: RequestHead{
			CircuitType: circuit,
			PublicInputHash: fb(spptest.MustHashChain4(t, []*big.Int{
				big.NewInt(shared.RegisterKeyDomain), ringID, member, nullifierPk, listTag,
				sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
			})),
		},
		RingID: fb(ringID), Member: fb(member), NullifierSecret: secret[:], EphSk: eph[:], AuditorPk: auditor[:],
	}
}

func fi(v int64) Field    { return Field{big.NewInt(v)} }
func fb(v *big.Int) Field { return Field{new(big.Int).Set(v)} }

// fz reads nil as zero, ringregistry leaves unset settings nil.
func fz(v *big.Int) Field {
	if v == nil {
		return fi(0)
	}
	return fb(v)
}

func limitFields(limits ringregistry.Limits) []Field {
	fields := make([]Field, len(limits))
	for i, limit := range limits {
		fields[i] = fz(limit)
	}
	return fields
}

func fieldsOf(values []*big.Int) []Field {
	out := make([]Field, len(values))
	for i, value := range values {
		out[i] = fb(value)
	}
	return out
}
