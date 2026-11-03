// Proves that the auditor can see who sent an anonymous transfer and what notes
// they spent, while the chain sees neither.
//
// Read after audit/audit.go, audit/layout.go, shared/utxo.go. Read before
// transfer/anonymous.go.

package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the stream sealing it to the auditor are statement values.
// 2. Every output slot is published, every UTXO is a ring output or an exit and carries no data hash and no ring data.
// 3. A ring output's owner is the identity of the owner key its record opens.
// 4. Every UTXO's amount lies below 2^64, a ring output's and an exit's record open its asset, amount and nullifier key, a dummy's record encrypts zeros.
// 5. Slot i's ciphertext is its record at the length its kind fixes.
// 6. Every spent UTXO lies below the published input count, ahead of every dummy, and belongs to the hidden sender.
// 7. A commitment key spends notes of the ring only and its evidence holds spent UTXO 0's hash and the prefix of every other spent hash, an entry key's evidence opens every spent UTXO under one nullifier key with no data.
// 8. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 9. The sender is spent UTXO 0's owner on a commitment key and the owner of SenderKey on an entry key.

type AnonymousOutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
}

func (o AnonymousOutputWires) utxoWires() shared.UtxoWires { return o.Output }

func (AnonymousOutputWires) carriesBlinding() bool { return false }

type Spent struct {
	SenderPkHash frontend.Variable
	// InputHashes are utxo * hash per slot, the input list of private_tx_hash.
	InputHashes []frontend.Variable
	Evidence    Evidence
}

// Spend holds every spent UTXO to the hidden sender, below the published count and ahead of every dummy.
func Spend(api frontend.API, rc frontend.Rangechecker, shape AnonymousAuditShape, inputs []shared.UtxoWires, inputCount, ringProgramID frontend.Variable, senderKey []frontend.Variable) Spent {
	// 1. Every input slot opens once, the steps below read the same wires.
	slots := make([]shared.Output, len(inputs))
	for i, input := range inputs {
		slots[i] = input.Open(api)
	}
	// 2. The sender is input 0's owner, or SenderKey's identity on an entry key.
	senderPkHash := anonymousSender(api, shape, slots, senderKey)
	// 3. SelectCount refuses a count outside 1 to the class, the count selects the evidence and the digest's length.
	count := ringgadget.SelectCount(api, inputCount, 1, shape.InputClass)
	spent := Spent{SenderPkHash: senderPkHash, Evidence: Evidence{Count: count}}
	previousUtxo := frontend.Variable(1)
	for i, slot := range slots {
		// 4. Every spent UTXO lies below the count and is the hidden sender's.
		hash := spentBySender(api, slot, count.Active[i], 1, senderPkHash, i)
		spent.InputHashes = append(spent.InputHashes, hash)
		if i > 0 {
			// 5. A UTXO follows only a UTXO as SPP's AssertDummiesLast holds, so spent UTXO k owns nullifier k.
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: api.Sub(1, previousUtxo)})
		}
		previousUtxo = slot.Utxo
		if shape.FullOpenings {
			spent.Evidence.Entries = append(spent.Evidence.Entries, entryInput(api, rc, slot, slots[0].NullifierPk))
			continue
		}
		// 6. An evidence hash names a note of the ring, an audited output whose opening the auditor holds.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.RingProgramID, B: ringProgramID})
		spent.Evidence.Entries = append(spent.Evidence.Entries, commitmentEntry(api, rc, hash, i))
	}
	if shape.FullOpenings {
		// 7. The head opens the sender key SolanaOwnerIdentity bounds and the nullifier key of input 0, a UTXO, every live entry holds the same key.
		nullifierPk := ringgadget.FieldToBytesBEWith(api, rc, slots[0].NullifierPk)
		spent.Evidence.Head = slices.Concat(senderKey, nullifierPk[:])
	}
	return spent
}

func anonymousSender(api frontend.API, shape AnonymousAuditShape, slots []shared.Output, senderKey []frontend.Variable) frontend.Variable {
	if shape.FullOpenings {
		return gadget.SolanaOwnerIdentity(api, [32]frontend.Variable(senderKey))
	}
	return slots[0].OwnerPkHash
}

// entryInput holds a live entry input to the one nullifier key with no data, zero bytes off a UTXO, mirrored by EntryInput in program-libs/interface/src/proof/audit_stream.rs.
//
//	u64be(amount) ‖ be32(asset) ‖ be32(blinding)
func entryInput(api frontend.API, rc frontend.Rangechecker, slot shared.Output, nullifierPk frontend.Variable) []frontend.Variable {
	// 1. The auditor rebuilds a live input's owner from the head's one nullifier key, another key would hide a note of another owner.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.NullifierPk, B: nullifierPk})
	// 2. The evidence opens no data, a data hash would commit a note the auditor cannot rebuild.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.DataHash})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.RingDataHash})
	// 3. FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Asset))
	blinding := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Blinding))
	return slices.Concat(ringgadget.UintBytesBE(api, api.Mul(slot.Utxo, slot.Amount), amountLen), asset[:], blinding[:])
}

// commitmentEntry is be32(input_hash_0) naming the sender on slot 0 and prefix16(input_hash_i) past it.
func commitmentEntry(api frontend.API, rc frontend.Rangechecker, hash frontend.Variable, i int) []frontend.Variable {
	if i > 0 {
		return inputPrefix(api, rc, hash)
	}
	bytes := ringgadget.FieldToBytesBEWith(api, rc, hash)
	return bytes[:]
}

// AnonymousRecords holds a ring output's owner key and returns every slot's record, zero on a dummy, mirrored by AnonymousRecord::encode in program-libs/interface/src/proof/audit_stream.rs.
//
//	owner_key ‖ be32(asset) ‖ u64be(amount) ‖ be32(nullifier_pk) on a ring output, the exit record on an exit
func (o Opened) AnonymousRecords(api frontend.API, outputs []AnonymousOutputWires) [][]frontend.Variable {
	records := make([][]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot, exitRecord := o.Slots[i], o.bytes[i].exitRecord()
		// 1. A ring output's owner is the identity of its owner key, SolanaOwnerIdentity bounds every byte the record reads.
		assertOwnerKey(api, slot, output.OwnerKey)
		ringRecord := slices.Concat(output.OwnerKey[:], exitRecord)
		// 2. Ring and Exit exclude each other and both clear on a dummy, every byte holds one kind and a dummy encrypts zeros.
		records[i] = make([]frontend.Variable, AnonymousRecordLen)
		for j := range records[i] {
			records[i][j] = api.Mul(slot.Ring, ringRecord[j])
			if j < ExitRecordLen {
				records[i][j] = api.Add(records[i][j], api.Mul(slot.Exit, exitRecord[j]))
			}
		}
	}
	return records
}

// RecordChain is HashChain4 of hash_bytes(record), 72 bytes on an exit and 104 otherwise, the program hashes the same bytes.
func (o Opened) RecordChain(api frontend.API, stream Stream) frontend.Variable {
	ciphertexts := make([]frontend.Variable, len(o.Slots))
	for i, slot := range o.Slots {
		record := stream.record(i)
		ciphertexts[i] = api.Select(slot.Exit, gadget.HashBoundedBytes(api, record[:ExitRecordLen]), gadget.HashBoundedBytes(api, record[:AnonymousRecordLen]))
	}
	return gadget.HashChain4(api, ciphertexts)
}

// spentBySender holds slot i to the sender and to live, slot 0 a UTXO while required, and returns its spent hash, zero off a UTXO.
func spentBySender(api frontend.API, slot shared.Output, live, required, sender frontend.Variable, i int) frontend.Variable {
	// An input at or past the count is no UTXO, so no spent UTXO escapes the published inputs.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, live), V: slot.Utxo})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.OwnerPkHash, B: sender})
	if i == 0 {
		// Input 0 is a UTXO while required, so the sender owns a real spent UTXO.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: required, V: api.Sub(1, slot.Utxo)})
	}
	return api.Mul(slot.Utxo, slot.Hash)
}
