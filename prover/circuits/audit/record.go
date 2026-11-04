// A dummy's plaintext is all zero, the auditor skips it by one byte under a proof.

package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// The record's kind byte, mirrored by RecordKind in program-libs/interface/src/proof/audit_stream.rs.
const (
	KindDummy = 0
	KindRing  = 1
	KindExit  = 2
)

type OutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
	// MintChunks open Asset to the 31 and 1 byte chunks of the raw mint.
	MintChunks [2]frontend.Variable
}

// Live clear masks every byte but Kind, a dummy's Kind derives to zero.
type RecordOpening struct {
	Live, Kind, Amount, OwnerPkHash, NullifierPk, Asset frontend.Variable
	OwnerKey                                            [32]frontend.Variable
	MintChunks                                          [2]frontend.Variable
}

// Encode mirrors AuditRecord::encode in program-libs/interface/src/proof/audit_stream.rs, padded to RecordStride.
func (r RecordOpening) Encode(api frontend.API, rc frontend.Rangechecker) []frontend.Variable {
	mint := assertMint(api, r.Live, r.Asset, r.MintChunks)
	// SolanaOwnerIdentity bounds every owner key byte, the reader rebuilds the owner from the key.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: r.Live, A: r.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, r.OwnerKey)})
	// FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
	nullifierPk := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(r.Live, r.NullifierPk))
	return slices.Concat([]frontend.Variable{r.Kind}, ringgadget.UintBytesBE(api, api.Mul(r.Live, r.Amount), amountLen), masked(api, r.Live, r.OwnerKey[:]), masked(api, r.Live, mint), nullifierPk[:], shared.Zeros(RecordStride-RecordLen))
}

func (o OutputWires) record(api frontend.API, rc frontend.Rangechecker, slot shared.Output) []frontend.Variable {
	return RecordOpening{
		Live: slot.Utxo, Kind: api.Add(api.Mul(slot.Ring, KindRing), api.Mul(slot.Exit, KindExit)),
		Amount: slot.Amount, OwnerPkHash: slot.OwnerPkHash, NullifierPk: slot.NullifierPk, Asset: slot.Asset,
		OwnerKey: o.OwnerKey, MintChunks: o.MintChunks,
	}.Encode(api, rc)
}

// assertMint holds a live asset to the raw mint the record carries, the auditor needs no mint registry.
func assertMint(api frontend.API, live, asset frontend.Variable, chunks [2]frontend.Variable) []frontend.Variable {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: live, A: asset, B: gadget.HashChain(api, chunks[:])})
	return slices.Concat(ringgadget.UintBytesBE(api, chunks[0], 31), ringgadget.UintBytesBE(api, chunks[1], 1))
}

// assertNoData holds both data hashes to zero while has_data is clear, no tail would open them.
func assertNoData(api frontend.API, hasData frontend.Variable, slot shared.Output) {
	cond := api.Sub(1, hasData)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: slot.DataHash})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: cond, V: slot.RingDataHash})
}

// dataTail mirrors DataTail::encode in program-libs/interface/src/proof/audit_stream.rs, zero off a note.
func dataTail(api frontend.API, rc frontend.Rangechecker, slot shared.Output) []frontend.Variable {
	dataHash := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.DataHash))
	ringDataHash := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.RingDataHash))
	return slices.Concat(dataHash[:], ringDataHash[:])
}

type EntryWires struct {
	OwnerKey   [32]frontend.Variable
	MintChunks [2]frontend.Variable
}

type SpentInputs struct {
	Slots []shared.Output
	// The published n, R may sit below it.
	Count   ringgadget.Count
	Entries []EntryWires
}

type evidence struct {
	head       []frontend.Variable
	entries    [][]frontend.Variable
	realInputs frontend.Variable
}

// evidence mirrors AuditEnvelope::encode in program-libs/interface/src/proof/audit_stream.rs past the sealed key.
func (s SpentInputs) evidence(api frontend.API, rc frontend.Rangechecker, ranges StreamRanges) evidence {
	if len(s.Slots) != ranges.InputClass {
		panic("audit: the input section differs from the key's class")
	}
	realInputs := frontend.Variable(0)
	defaults := make([]frontend.Variable, len(s.Slots))
	for i, slot := range s.Slots {
		// OpenInputs holds dummies last, position below R is a spend.
		realInputs = api.Add(realInputs, slot.Utxo)
		defaults[i] = slot.Exit
	}
	head := ringgadget.UintBytesBE(api, realInputs, RealInputCountLen)
	if !ranges.Entry {
		// A key with no entry capacity carries no evidence, a default-ring spend under it would stay unreadable.
		for _, slot := range s.Slots {
			api.AssertIsEqual(slot.Exit, 0)
		}
		return evidence{head: head, realInputs: realInputs}
	}
	if len(s.Entries) != len(s.Slots) {
		panic("audit: an entry key needs one evidence wire per input")
	}
	head = slices.Concat(head, ringgadget.UintBytesBE(api, weightedBits(api, defaults), DefaultInputBitsLen))
	entries := make([][]frontend.Variable, len(s.Slots))
	for i, slot := range s.Slots {
		entries[i] = s.Entries[i].encode(api, rc, slot)
	}
	return evidence{head: head, entries: entries, realInputs: realInputs}
}

// encode mirrors EntryInput::extend in program-libs/interface/src/proof/audit_stream.rs, zero off a default-ring note.
func (e EntryWires) encode(api frontend.API, rc frontend.Rangechecker, slot shared.Output) []frontend.Variable {
	live := slot.Exit
	mint := assertMint(api, live, slot.Asset, e.MintChunks)
	// Per input owner and key, mixed owners read apart with no nullifier secret disclosed.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: live, A: slot.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, e.OwnerKey)})
	field := func(value frontend.Variable) []frontend.Variable {
		bytes := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(live, value))
		return bytes[:]
	}
	return slices.Concat(
		masked(api, live, e.OwnerKey[:]), field(slot.NullifierPk),
		ringgadget.UintBytesBE(api, api.Mul(live, slot.Amount), amountLen),
		masked(api, live, mint), field(slot.Blinding), field(slot.DataHash), field(slot.RingDataHash),
	)
}

func weightedBits(api frontend.API, bits []frontend.Variable) frontend.Variable {
	bitmap := frontend.Variable(0)
	for i, bit := range bits {
		bitmap = api.Add(bitmap, api.Mul(bit, uint64(1)<<i))
	}
	return bitmap
}
