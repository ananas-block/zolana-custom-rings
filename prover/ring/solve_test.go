package ring

import (
	"encoding/json"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

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
	wideKey       common.CircuitType = "custom-ring-transfer-wide-8-in24-w32-s24"
	wide49Key     common.CircuitType = "custom-ring-transfer-wide-2-in49-w4-s12"
	wide16Key     common.CircuitType = "custom-ring-transfer-wide-16-in5-w8-s5"
	entryKey      common.CircuitType = "custom-ring-transfer-entry-4-in8-w4-s8"
	entry24Key    common.CircuitType = "custom-ring-transfer-entry-2-in24-w32-s12"
	entry8Key     common.CircuitType = "custom-ring-transfer-entry-8-in2-w4-s2"
	applyKey      common.CircuitType = "custom-ring-apply-records-1"
	batchKey      common.CircuitType = "custom-ring-apply-records-16"
	registerKey   common.CircuitType = "custom-ring-register-key"
	depositKey    common.CircuitType = "custom-ring-deposit-8"
	mergeKey      common.CircuitType = "custom-ring-merge"
)

func TestHostRequestsDecodeAndSolve(t *testing.T) {
	for _, circuit := range []common.CircuitType{transferKey, transfer4Key, transfer8Key, transfer16Key, wideKey, wide16Key, wide49Key, entryKey, entry8Key, entry24Key, applyKey, batchKey, registerKey, depositKey, mergeKey} {
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
	// A nonzero chain start, as `chain_start` derives from the registry and revision.
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
		ChainStart: fb(batch.chainStart), Count: uint8(len(entries)), Writes: make([]*RecordWriteProofInput, batch.capacity),
		PrivateRingID: fi(0), CredentialOwner: fi(0), AddressRoot: fi(0),
		StateRoots: make([]CredentialStateRoot, batch.capacity), Credentials: make([]*CredentialWriteParams, batch.capacity),
	}
	for i := range p.StateRoots {
		p.StateRoots[i].Root = fi(0)
	}
	chain := p.ChainStart.Int
	for i, e := range entries {
		w := members.Apply(t, e)
		chain = ringtest.MustPoseidonHash(t, chain, e.Hash(t))
		p.Writes[i] = requestValue[RecordWriteProofInput](t, w.Wires())
	}
	p.NewRoot, p.NewNextIndex, p.ChainEnd = fb(members.Root()), uint32(members.NextIndex()), fb(chain)
	fields := []*big.Int{
		big.NewInt(shared.ApplyRecordsDomain), p.OldRoot.Int, p.NewRoot.Int, big.NewInt(int64(p.OldNextIndex)),
		big.NewInt(int64(p.NewNextIndex)), p.ChainStart.Int, p.ChainEnd.Int, big.NewInt(int64(p.Count)),
		new(big.Int), p.PrivateRingID.Int, p.CredentialOwner.Int, p.AddressRoot.Int,
	}
	for range p.StateRoots {
		fields = append(fields, new(big.Int), new(big.Int))
	}
	p.PublicInputHash = fb(spptest.MustHashChain4(t, fields))
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

func registerKeyRequest(t testing.TB, circuit common.CircuitType, member *big.Int) *RegisterKeyParams {
	t.Helper()
	keys := ringaudit.DefaultKeys(t)
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	salt := ringtest.Scalar(0x09)
	salt[0] = 0
	sealed := keys.SealStream(t, slices.Concat(secret[:], salt[:]), shared.NfKeyEncInfo)
	secretField := new(big.Int).SetBytes(secret[1:])
	nullifierPk := spptest.MustNullifierPk(t, secretField)
	ringID := big.NewInt(0x7711)
	listTag := ringregistry.ListTag(t, new(big.Int).SetBytes(salt[1:]))
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	return &RegisterKeyParams{
		RequestHead: RequestHead{
			CircuitType: circuit,
			PublicInputHash: fb(spptest.MustHashChain4(t, []*big.Int{
				big.NewInt(shared.RegisterKeyDomain), ringID, member, nullifierPk, listTag,
				sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
			})),
		},
		RingID: fb(ringID), Member: fb(member), NullifierSecret: secret[:], ListSalt: salt[:], EphSk: eph[:], AuditorPk: auditor[:],
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
