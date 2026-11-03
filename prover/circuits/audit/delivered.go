// Proves that each recipient and the auditor read the same note bytes of a
// confidential or delegate transfer. A false encrypted note would leave the
// recipient with funds it cannot spend.
//
// Read after audit/audit.go, audit/layout.go, ringgadget/bytes.go. Read before
// transfer/confidential.go.

package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the stream sealing it to the auditor are statement values.
// 2. The output chain covers every slot, a delivered transfer publishes no prefix.
// 3. Every UTXO is a ring output or an exit and carries no output data.
// 4. A ring output's body encrypts be32(blinding) ‖ u64be(amount) ‖ owner_key ‖ be32(nullifier_pk) under CRING/bdy1 over its CRDS slot secret for the holder of its canonical recipient key and the auditor.
// 5. Under LayoutEscrow the body's equality covers its first 72 bytes, the cipher still runs over all 104.
// 6. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 7. A ring output's owner is the identity of the owner key its body names.
// 8. Every exit's record in the auditor stream opens its asset and amount, and its nullifier key unless LayoutEscrow.
// 9. Slot i's ciphertext hash is its record's on an exit and its body's otherwise, each at the length LayoutEscrow fixes, a dummy's body is free bytes the statement still binds.

type DeliveryWires struct {
	Output shared.UtxoWires
	// RecipientKey is the X25519 u the body is sealed to.
	RecipientKey [32]frontend.Variable
	OwnerKey     [32]frontend.Variable
	// Body past EscrowBodyLen reaches neither the equality nor the selected hash under LayoutEscrow.
	Body [shared.BodyLen]frontend.Variable
}

func (d DeliveryWires) utxoWires() shared.UtxoWires { return d.Output }

func (DeliveryWires) carriesBlinding() bool { return true }

type Delivered struct {
	OutputCiphertextChain, RecipientKeyChain frontend.Variable
}

// ExitRecords is one record per slot, Deliver reads the region of an exit alone and every other region leaves no bytes.
func (o Opened) ExitRecords() [][]frontend.Variable {
	records := make([][]frontend.Variable, len(o.bytes))
	for i, bytes := range o.bytes {
		records[i] = bytes.exitRecord()
	}
	return records
}

// Deliver holds each ring output's body to its opening and chains one ciphertext per slot.
func (w AuditWires) Deliver(api frontend.API, e Envelope, keyEscrow frontend.Variable, outputs []DeliveryWires, opened Opened, stream Stream) Delivered {
	var ciphertexts, recipientKeys []frontend.Variable
	for i, output := range outputs {
		slot := opened.Slots[i]
		// 1. Every ring output body opens for the holder of its published recipient key.
		w.deliver(api, e, keyEscrow, output, slot, opened.bytes[i], i)
		// 2. Each slot chains the one ciphertext the program hashes from the frame.
		ciphertexts = append(ciphertexts, slotCiphertextHash(api, keyEscrow, output, slot, stream.record(i)))
		// 3. The program rebuilds the owner tag from the published key, zero on an exit.
		recipientKeys = append(recipientKeys, recipientKeyFields(api, output, slot)...)
	}
	return Delivered{
		OutputCiphertextChain: gadget.HashChain4(api, ciphertexts),
		RecipientKeyChain:     gadget.HashChain4(api, recipientKeys),
	}
}

// slotCiphertextHash is hash_bytes of the record on an exit and of the body otherwise, LayoutEscrow picks 40 or 72 record bytes and 72 or 104 body bytes, mirrored by slot_ciphertext_hash in program-libs/interface/src/proof/statement.rs.
func slotCiphertextHash(api frontend.API, keyEscrow frontend.Variable, d DeliveryWires, slot shared.Output, record []frontend.Variable) frontend.Variable {
	body := api.Select(keyEscrow, gadget.HashBoundedBytes(api, d.Body[:shared.EscrowBodyLen]), gadget.HashBoundedBytes(api, d.Body[:]))
	exit := api.Select(keyEscrow, gadget.HashBoundedBytes(api, record[:EscrowExitRecordLen]), gadget.HashBoundedBytes(api, record[:ExitRecordLen]))
	return api.Select(slot.Exit, exit, body)
}

// recipientKeyFields is pack_be(u) masked off an exit, the agreement's ECDH bounds a ring output's key bytes.
func recipientKeyFields(api frontend.API, d DeliveryWires, slot shared.Output) []frontend.Variable {
	key, notExit := shared.PackBounded(api, d.RecipientKey[:]), api.Sub(1, slot.Exit)
	return []frontend.Variable{api.Mul(notExit, key[0]), api.Mul(notExit, key[1])}
}

func recipientKey(api frontend.API, slot shared.Output, key [32]frontend.Variable) [32]frontend.Variable {
	var u [32]frontend.Variable
	for j := range u {
		// A slot without a recipient agrees with the base point, the ladder stays satisfiable on every slot.
		u[j] = api.Select(slot.Ring, key[j], basepointByte(j))
	}
	return u
}

// deliver holds a ring output's body to its opening for the holder of its recipient key, mirrored by DeliveredBody::encode in program-libs/interface/src/proof/audit_stream.rs.
//
//	be32(blinding) ‖ u64be(amount) ‖ owner_key ‖ be32(nullifier_pk), the last field cut under LayoutEscrow
func (w AuditWires) deliver(api frontend.API, e Envelope, keyEscrow frontend.Variable, d DeliveryWires, slot shared.Output, bytes slotBytes, i int) {
	u := recipientKey(api, slot, d.RecipientKey)
	// 1. One encoding per recipient key, an alias would key the slot secret and the owner tag to bytes the recipient never derives.
	agreement := shared.AgreeCanonical(api, e.txViewingSk, u)
	// 2. The agreement's ECDH bounds every byte of u and returns canonical agreement bytes.
	recipient := [2]frontend.Variable(shared.PackBounded(api, shared.Tagged(u)))
	// 3. The slot secret binds the agreement, both keys, the salt, the slot and n0, no two slots share a keystream.
	secret := shared.DeliveredSlot{
		Agreement:      [2]frontend.Variable(shared.PackBounded(api, agreement[:])),
		TxPk:           e.txPk,
		Recipient:      recipient,
		Salt:           e.salt,
		OutputIndex:    i,
		FirstNullifier: w.FirstNullifier,
	}.Secret(api)
	// 4. The CRING/bdy1 label separates a body's key from every other line over one secret.
	key, nonce := shared.AuditStreamKeySchedule(api, secret, shared.BodyEncInfo)
	// 5. A ring output's body is the encryption of its opening, the recipient and the auditor decrypt the same bytes.
	ciphertext := aes.NewCipher(api, key).CTREncrypt(nonce, slices.Concat(bytes.blinding[:], bytes.amount, d.OwnerKey[:], bytes.nullifierPk[:]))
	withNullifierKey := api.Mul(slot.Ring, api.Sub(1, keyEscrow))
	for j, b := range ciphertext {
		cond := slot.Ring
		if j >= shared.EscrowBodyLen {
			// LayoutEscrow clears the equality alone, the policy's assertEscrow holds the nullifier key.
			cond = withNullifierKey
		}
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: d.Body[j], B: b})
	}
	// 6. A ring output's owner is the identity of the key the body names, a recipient compares it with its own.
	assertOwnerKey(api, slot, d.OwnerKey)
}

func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
