// Proves that the auditor can see who sent an anonymous transfer and what notes
// they spent, while the chain sees neither.
//
// Read after audit/audit.go, audit/layout.go, shared/utxo.go. Read before
// transfer/anonymous.go.

package audit

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. Every output slot is published, every UTXO is a ring output or an exit and carries no data hash and no ring data.
// 3. A ring output's owner is the identity of the owner key the disclosure opens.
// 4. Every UTXO's amount lies below 2^64, the disclosure opens every UTXO's asset and amount and leaves a dummy slot zero.
// 5. Every exit discloses its full opening to the auditor, SeedOut opens the disclosure exactly when a UTXO exits.
// 6. Every spent UTXO lies below the published input count, ahead of every dummy, and belongs to the hidden sender.
// 7. A commitment key spends notes of the ring only and discloses spent UTXO 0's hash and the prefix of every other spent hash, an entry key opens every spent UTXO under one nullifier key with no data.
// 8. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 9. The sender is spent UTXO 0's owner on a commitment key and the owner of SenderKey on an entry key.

const (
	// InputPrefixLen is the byte width of a spent hash's prefix on a commitment key.
	InputPrefixLen = 16
	// InputPrefixBits bounds a prefix of a canonical hash, two of them pack below q.
	InputPrefixBits = 126
)

type AnonymousOutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
}

type anonymousSlot struct {
	shared.Output
	// bytes is mask(ring, owner_key) ‖ be32(live * asset) ‖ u64be(live * amount), mirrored by ANONYMOUS_SLOT_BYTES in program-libs/interface/src/proof/disclosure.rs.
	bytes []frontend.Variable
}

type spentInputs struct {
	count ringgadget.Count
	// hashes are the private_tx_hash input hashes, zero off a UTXO.
	hashes []frontend.Variable
	// tail is the disclosure of the input slots, zero off a UTXO.
	tail countedTail
	// amounts are u64be(amount) of every input slot on an entry key, zero off a UTXO.
	amounts []frontend.Variable
}

// Anonymous is the audit of every output slot and spent note of an anonymous transfer.
type Anonymous struct {
	Slots       []shared.Output
	OutputChain frontend.Variable
	// SenderPkHash is spent UTXO 0's owner on a commitment key and the owner of SenderKey on an entry key.
	SenderPkHash frontend.Variable
	// InputHashes are utxo * hash per input slot, the input list of private_tx_hash.
	InputHashes  []frontend.Variable
	shape        AnonymousAuditShape
	senderKey    []frontend.Variable
	inputs       []shared.UtxoWires
	nullifierPks []frontend.Variable
	slotBytes    []frontend.Variable
	spent        spentInputs
}

// Anonymous opens every output slot to the auditor and holds every spent UTXO to the hidden sender, below inputCount and ahead of every dummy.
func (w AuditWires) Anonymous(api frontend.API, rc frontend.Rangechecker, e Envelope, layout Layout, shape AnonymousAuditShape, outputs []AnonymousOutputWires, inputs []shared.UtxoWires, inputCount frontend.Variable, senderKey []frontend.Variable) Anonymous {
	senderPkHash := anonymousSender(api, shape, inputs, senderKey)
	slots := make([]shared.Output, len(outputs))
	var hashes, nullifierPks, slotBytes []frontend.Variable
	for i, output := range outputs {
		s := w.openSlot(api, rc, e, output, i)
		slots[i] = s.Output
		hashes = append(hashes, s.Hash)
		nullifierPks = append(nullifierPks, api.Mul(s.Utxo, s.NullifierPk))
		slotBytes = append(slotBytes, s.bytes...)
	}
	layout.AssertExits(api, slots)
	spent := spend(api, rc, shape, inputs, inputCount, senderPkHash, w.RingProgramID)
	return Anonymous{
		Slots:        slots,
		OutputChain:  gadget.HashChain4(api, hashes),
		SenderPkHash: senderPkHash,
		InputHashes:  spent.hashes,
		shape:        shape,
		senderKey:    senderKey,
		inputs:       inputs,
		nullifierPks: nullifierPks,
		slotBytes:    slotBytes,
		spent:        spent,
	}
}

func anonymousSender(api frontend.API, shape AnonymousAuditShape, inputs []shared.UtxoWires, senderKey []frontend.Variable) frontend.Variable {
	if shape.FullOpenings {
		return gadget.SolanaOwnerIdentity(api, [32]frontend.Variable(senderKey))
	}
	return inputs[0].OwnerPkHash
}

func (w AuditWires) openSlot(api frontend.API, rc frontend.Rangechecker, e Envelope, o AnonymousOutputWires, i int) anonymousSlot {
	slot := OpenOutput(api, o.Output)
	w.AssertBlinding(api, e, slot, i)
	// 1. No UTXO carries ring data the auditor cannot open.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.RingDataHash})
	// 2. The identity gadget bounds every owner key byte the disclosure packs.
	assertOwnerKey(api, slot, o.OwnerKey)
	// 3. be32 is the one asset encoding below q, the decomposition bounds a live amount below 2^64.
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Asset))
	amount := ringgadget.UintBytesBE(api, api.Mul(slot.Utxo, slot.Amount), 8)
	return anonymousSlot{Output: slot, bytes: slices.Concat(masked(api, slot.Ring, o.OwnerKey[:]), asset[:], amount)}
}

// spend proves every spent UTXO is the hidden sender's and lies below the published count.
func spend(api frontend.API, rc frontend.Rangechecker, shape AnonymousAuditShape, inputs []shared.UtxoWires, inputCount, senderPkHash, ringProgramID frontend.Variable) spentInputs {
	// 1. The published field count pins the input count, up to one trailing dummy on a commitment key.
	spent := spentInputs{count: ringgadget.SelectCount(api, inputCount, 1, shape.InputClass)}
	var openings [][]frontend.Variable
	previousUtxo := frontend.Variable(1)
	for i, input := range inputs {
		// 2. Every spent UTXO lies below the count and is the hidden sender's.
		opened, hash := spentBySender(api, input, spent.count.Active[i], 1, senderPkHash, i)
		spent.hashes = append(spent.hashes, hash)
		if !shape.FullOpenings {
			// 3. A disclosed hash names a note of the ring, an audited output whose opening the auditor holds.
			abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.RingProgramID, B: ringProgramID})
		}
		if i > 0 {
			// 4. A UTXO follows only a UTXO as in SPP, so spent UTXO k owns nullifier k.
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: api.Sub(1, previousUtxo)})
		}
		previousUtxo = opened.Utxo
		if !shape.FullOpenings {
			continue
		}
		// 5. The auditor rebuilds an entry input from its opening, under input 0's nullifier key and with no data.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.NullifierPk, B: inputs[0].NullifierPk})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.DataHash})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: input.RingDataHash})
		spent.amounts = append(spent.amounts, ringgadget.UintBytesBE(api, api.Mul(opened.Utxo, input.Amount), 8)...)
		openings = append(openings, []frontend.Variable{api.Mul(opened.Utxo, input.Asset), api.Mul(opened.Utxo, input.Blinding)})
	}
	if shape.FullOpenings {
		spent.tail = uniformTail(openings)
		return spent
	}
	// 5. Input 0 opens by its hash and names the sender, every other spent UTXO matches among the sender's notes by its prefix.
	spent.tail = countedTail{fields: commitmentTail(api, rc, spent.hashes), published: func(n int) int { return 1 + n/2 }}
	return spent
}

// Disclosure is the anonymous disclosure the layout selects, mirrored by DisclosureLayout::Anonymous in program-libs/interface/src/proof/disclosure.rs.
//
//	SeedOut under LayoutExits, then on a commitment key
//	nullifier_pk per output, pack_disclosure(slot bytes per output), hash of input 0, prefix pairs of the other published inputs
//	and on an entry key
//	sender nullifier_pk, nullifier_pk per output, pack_disclosure(sender_key ‖ slot bytes per output),
//	pack_disclosure(u64be(amount) per input slot), asset and blinding per published input
func (a Anonymous) Disclosure(api frontend.API, e Envelope, layout Layout) frontend.Variable {
	// SolanaOwnerIdentity bounds the sender key bytes, openSlot the slot bytes.
	head := slices.Concat(a.nullifierPks, shared.PackDisclosure(api, slices.Concat(a.senderKey, a.slotBytes)))
	if a.shape.FullOpenings {
		// Input 0 is a UTXO, its key is the key of every spent UTXO.
		head = slices.Concat([]frontend.Variable{a.inputs[0].NullifierPk}, head, shared.PackDisclosure(api, a.spent.amounts))
	}
	return e.disclose(api, layout.choices(api, LayoutExits), func(choice layoutChoice) disclosureLayout {
		return choice.counted(api, slices.Concat(e.seedOut(choice), head), a.spent.tail, a.spent.count)
	})
}

// spentBySender holds slot i to the sender and to live, slot 0 a UTXO while required, and returns its spent hash, zero off a UTXO.
func spentBySender(api frontend.API, input shared.UtxoWires, live, required, sender frontend.Variable, i int) (shared.Output, frontend.Variable) {
	opened := input.Open(api)
	// An input at or past the count is no UTXO, so no spent UTXO escapes the published inputs.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, live), V: opened.Utxo})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: opened.Utxo, A: input.OwnerPkHash, B: sender})
	if i == 0 {
		// Input 0 is a UTXO while required, so the sender owns a real spent UTXO.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: required, V: api.Sub(1, opened.Utxo)})
	}
	return opened, api.Mul(opened.Utxo, opened.Hash)
}

// commitmentTail is hashes[0] in full, then the prefixes of the other hashes two per field, the last half zero for an odd prefix count.
func commitmentTail(api frontend.API, rc frontend.Rangechecker, hashes []frontend.Variable) []frontend.Variable {
	prefixes := make([]frontend.Variable, 0, len(hashes))
	for _, hash := range hashes[1:] {
		// The canonical split leaves one prefix per hash, the prefix of hash + q would name another note.
		prefix, _ := ringgadget.SplitField(api, rc, hash, 8*(32-InputPrefixLen))
		prefixes = append(prefixes, prefix)
	}
	shift := new(big.Int).Lsh(big.NewInt(1), InputPrefixBits)
	tail := []frontend.Variable{hashes[0]}
	for k := 0; k < len(prefixes); k += 2 {
		second := frontend.Variable(0)
		if k+1 < len(prefixes) {
			second = prefixes[k+1]
		}
		// Both prefixes lie below 2^InputPrefixBits, the pair packs without a wrap and decodes to one pair.
		tail = append(tail, api.Add(api.Mul(prefixes[k], shift), second))
	}
	return tail
}
