// Proves that the auditor can see who sent an anonymous transfer and what notes
// they spent, and that every recipient and the sender read their note bytes under
// an address the owner authorized, while the chain sees neither.
//
// Read after audit/audit.go, audit/layout.go, shared/utxo.go, registry/registry.go.
// Read before transfer/anonymous.go.

package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 2. Every published slot is hashed, every UTXO is a ring output or an exit and carries no data hash and no ring data.
// 8. Every published slot's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 10. Every live ring slot's owner, nullifier key and viewing key open the owner's bound address under the ring.
// 11. A slot is change exactly when its address equals the sender's, every other live ring slot's body encrypts its opening to the bound key.
// 12. The bundle encrypts the change amounts and every recipient key to the sender's bound key.
// 13. A live recipient's tag and the bundle's tag derive from their slot secrets, a published dummy's tag holds a Poseidon(CRRT, s) preimage, change, exit and omitted slots carry zero.

type AnonymousOutputWires struct {
	Output   shared.UtxoWires
	OwnerKey [32]frontend.Variable
	// X25519 u the owner's address binds.
	RecipientKey    [32]frontend.Variable
	AddressRevision frontend.Variable
	// MintChunks open Asset to the 31 and 1 byte chunks of the mint a body names.
	MintChunks [2]frontend.Variable
	// Body is hashed as sent on a published dummy.
	Body [shared.RecipientBodyLen]frontend.Variable
	// Tag is the frame's discovery tag, zero on change, an exit and an omitted slot.
	Tag frontend.Variable
	// TagPreimage opens a published dummy's Tag, a live slot reads its slot secret.
	TagPreimage frontend.Variable
}

func (o AnonymousOutputWires) utxoWires() shared.UtxoWires { return o.Output }

// The key need not be input 0's, an older note spends into change at the bound address.
type SenderAddress struct {
	SenderNullifierPk     frontend.Variable
	SenderViewingKey      [32]frontend.Variable
	SenderAddressRevision frontend.Variable
	SenderBundleTag       frontend.Variable
}

// AddressRows are the address hashes the pool opened, zero off a record.
type AddressRows struct {
	Sender frontend.Variable
	Owners []frontend.Variable
}

type RecipientDelivery struct {
	ChangeBitmap, RecipientBodyChain, RecipientTagChain, SenderBundleDigest frontend.Variable
}

// DeliverRecipients binds every delivery ciphertext to the addresses rows hold, sender the identity the rail's inputs name.
func (w AuditWires) DeliverRecipients(api frontend.API, rc frontend.Rangechecker, e Envelope, outputs []AnonymousOutputWires, opened Opened, sender frontend.Variable, address SenderAddress, rows AddressRows) RecipientDelivery {
	// 1. The sender's row holds its address, every other wire of the bundle's key then follows the owner's enrollment.
	senderView := [2]frontend.Variable(shared.PackBounded(api, address.SenderViewingKey[:]))
	senderHash := registry.Address{RingID: w.RingProgramID, Member: sender, NullifierPk: address.SenderNullifierPk, View: senderView, Revision: address.SenderAddressRevision}.Hash(api)
	api.AssertIsEqual(senderHash, rows.Sender)
	cells := make([][]frontend.Variable, len(outputs))
	changes := make([]frontend.Variable, len(outputs))
	mints := make([][]frontend.Variable, len(outputs))
	bodies := make([]frontend.Variable, len(outputs))
	tags := make([]frontend.Variable, len(outputs)+1)
	for i, output := range outputs {
		slot := opened.Slots[i]
		view := [2]frontend.Variable(shared.PackBounded(api, output.RecipientKey[:]))
		// 2. A live ring slot opens its owner's row, a wrong key under a correct viewing key opens no record and an absent record never matches.
		hash := registry.Address{RingID: w.RingProgramID, Member: slot.OwnerPkHash, NullifierPk: slot.NullifierPk, View: view, Revision: output.AddressRevision}.Hash(api)
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: hash, B: rows.Owners[i]})
		// 3. Change is the exact address match.
		changes[i] = api.Mul(slot.Ring, isEqual(api, slot.OwnerPkHash, sender), isEqual(api, slot.NullifierPk, address.SenderNullifierPk), isEqual(api, view[0], senderView[0]), isEqual(api, view[1], senderView[1]))
		live := api.Sub(slot.Ring, changes[i])
		// A mint off the asset would decrypt to a note the recipient cannot rebuild.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: slot.Asset, B: gadget.HashChain(api, output.MintChunks[:])})
		mints[i] = slices.Concat(ringgadget.UintBytesBE(api, output.MintChunks[0], 31), ringgadget.UintBytesBE(api, output.MintChunks[1], 1))
		// 4. A live slot's body is the encryption of its opening, a false body leaves the recipient with funds it cannot spend.
		secret := w.assertRecipientBody(api, e, output, slices.Concat(opened.bytes[i].blinding[:], opened.bytes[i].amount, mints[i]), live, i)
		// A change or exit slot sends no body, a published dummy's bytes hash as sent.
		carrier := api.Sub(opened.Count.Active[i], slot.Exit, changes[i])
		bodies[i] = api.Mul(carrier, gadget.HashBoundedBytes(api, output.Body[:]))
		assertSlotTag(api, output, secret, live, carrier)
		tags[i] = output.Tag
		cells[i] = masked(api, live, output.RecipientKey[:])
	}
	digest, bundleSecret := w.sealSenderBundle(api, rc, e, opened, address, changes, mints, cells)
	// 5. The bundle's tag derives from its secret, a relayed proof cannot hide the transaction from its sender.
	api.AssertIsEqual(address.SenderBundleTag, gadget.PoseidonHash(api, []frontend.Variable{shared.SenderTagDomain, bundleSecret}))
	tags[len(outputs)] = address.SenderBundleTag
	return RecipientDelivery{
		ChangeBitmap:       weightedBits(api, changes),
		RecipientBodyChain: gadget.HashChain4(api, bodies),
		RecipientTagChain:  gadget.HashChain4(api, tags),
		SenderBundleDigest: digest,
	}
}

// assertSlotTag reads live and carrier from the opened slot, a live slot cannot take the dummy's preimage.
func assertSlotTag(api frontend.API, output AnonymousOutputWires, secret, live, carrier frontend.Variable) {
	preimage := api.Select(live, secret, output.TagPreimage)
	// A live tag off its secret would hide the note from its recipient's scan, a dummy tag needs a preimage under the same domain.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: carrier, A: output.Tag, B: gadget.PoseidonHash(api, []frontend.Variable{shared.RecipientTagDomain, preimage})})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, carrier), V: output.Tag})
}

// assertRecipientBody returns the slot secret the tag reuses, no second agreement runs.
func (w AuditWires) assertRecipientBody(api frontend.API, e Envelope, output AnonymousOutputWires, plaintext []frontend.Variable, live frontend.Variable, i int) frontend.Variable {
	secret := w.slotSecret(api, e, recipientKey(api, live, output.RecipientKey), i)
	// The CRING/rcp1 label separates a body's key from every other line over one secret.
	key, nonce := shared.AuditStreamKeySchedule(api, secret, shared.RecipientBodyEncInfo)
	for j, b := range aes.NewCipher(api, key).CTREncrypt(nonce, plaintext) {
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: live, A: output.Body[j], B: b})
	}
	return secret
}

// sealSenderBundle mirrors SenderBundle::encode in program-libs/interface/src/proof/audit_stream.rs.
func (w AuditWires) sealSenderBundle(api frontend.API, rc frontend.Rangechecker, e Envelope, opened Opened, address SenderAddress, changes []frontend.Variable, mints, cells [][]frontend.Variable) (digest, secret frontend.Variable) {
	// A change note in slot 1 is native SOL, the bundle carries one mint.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: changes[1], A: opened.Slots[1].Asset, B: shared.SolAssetField})
	seed := ringgadget.FieldToBytesBEWith(api, rc, e.outputSeed)
	plaintext := slices.Concat(masked(api, changes[0], mints[0]), masked(api, changes[0], opened.bytes[0].amount), masked(api, changes[1], opened.bytes[1].amount), seed[:], slices.Concat(cells...))
	// The index m lies past every body's index, the bundle shares no keystream with a slot.
	secret = w.slotSecret(api, e, address.SenderViewingKey, opened.OutputCount)
	key, nonce := shared.AuditStreamKeySchedule(api, secret, shared.SenderBundleEncInfo)
	return countedDigest(api, aes.NewCipher(api, key).CTREncrypt(nonce, plaintext), shared.SenderBundleHeadLen, fieldLen, opened.Count), secret
}

// EntryEvidence mirrors the entry layout of AuditEnvelope in program-libs/interface/src/proof/audit_stream.rs, the input of a default-ring note the auditor has never seen.
func EntryEvidence(api frontend.API, rc frontend.Rangechecker, slots []shared.Output, hashes []frontend.Variable, senderKey []frontend.Variable, count ringgadget.Count) Evidence {
	nullifierPk := slots[0].NullifierPk
	entries := make([][]frontend.Variable, len(slots))
	for i, slot := range slots {
		// The auditor rebuilds a live input's owner from the head's one nullifier key, another key would hide a note of another owner.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.NullifierPk, B: nullifierPk})
		// A data hash would commit a note the auditor cannot rebuild.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.DataHash})
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: slot.RingDataHash})
		// FieldToBytesBEWith holds the one be32 below q, UintBytesBE fails a live amount at or above 2^64.
		hash := ringgadget.FieldToBytesBEWith(api, rc, hashes[i])
		asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Asset))
		blinding := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(slot.Utxo, slot.Blinding))
		entries[i] = slices.Concat(hash[:], ringgadget.UintBytesBE(api, api.Mul(slot.Utxo, slot.Amount), amountLen), asset[:], blinding[:])
	}
	// SolanaOwnerIdentity bounds the sender key, FieldToBytesBEWith the head's nullifier key.
	nullifierPkBytes := ringgadget.FieldToBytesBEWith(api, rc, nullifierPk)
	return Evidence{Head: slices.Concat(senderKey, nullifierPkBytes[:]), Entries: entries, Count: count}
}

// AnonymousRecords mirrors AnonymousRecord::encode in program-libs/interface/src/proof/audit_stream.rs, zero on a dummy.
func (o Opened) AnonymousRecords(api frontend.API, outputs []AnonymousOutputWires) [][]frontend.Variable {
	records := make([][]frontend.Variable, len(outputs))
	for i, output := range outputs {
		slot, exitRecord := o.Slots[i], o.bytes[i].exitRecord()
		// SolanaOwnerIdentity bounds every owner key byte the record reads.
		assertOwnerKey(api, slot, output.OwnerKey)
		ringRecord := slices.Concat(output.OwnerKey[:], exitRecord)
		// Ring and Exit exclude each other and both clear on a dummy, every byte holds one kind and a dummy encrypts zeros.
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

// RecordChain hashes the bytes the program hashes, at the length the slot's kind fixes, zero past the published count.
func (o Opened) RecordChain(api frontend.API, stream Stream) frontend.Variable {
	ciphertexts := make([]frontend.Variable, len(o.Slots))
	for i, slot := range o.Slots {
		record := stream.record(i)
		ciphertexts[i] = api.Mul(o.Count.Active[i], api.Select(slot.Exit, gadget.HashBoundedBytes(api, record[:ExitRecordLen]), gadget.HashBoundedBytes(api, record[:AnonymousRecordLen])))
	}
	return gadget.HashChain4(api, ciphertexts)
}

func isEqual(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}
