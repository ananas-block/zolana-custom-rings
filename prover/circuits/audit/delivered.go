// Proves that each recipient and the auditor can open the notes of a
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

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. tx_viewing_sk is clamped, its tagged public key and the envelope sealing it to the auditor are statement values.
// 2. The output chain covers every slot, a delivered transfer publishes no prefix.
// 3. Every UTXO is a ring output or an exit and carries no output data.
// 4. A ring output's body encrypts be32(blinding) ‖ u64be(amount) under its CRDS slot secret for the holder of its canonical recipient key and the auditor.
// 5. Every UTXO's blinding is SPP's TXOB blinding over the seed tx_viewing_sk fixes.
// 6. The disclosure opens a ring output's owner key and every UTXO's nullifier key, LayoutEscrow leaves the keys to the policy's escrow records.
// 7. Every exit discloses its full opening, SeedOut and slots of 40 bytes appear exactly when a UTXO exits.

type DeliveryWires struct {
	Output shared.UtxoWires
	// RecipientKey is the X25519 u the body is sealed to.
	RecipientKey [32]frontend.Variable
	OwnerKey     [32]frontend.Variable
	Body         [shared.BodyLen]frontend.Variable
}

// Delivered is the audit of every slot of a confidential or authority transfer.
type Delivered struct {
	Slots                                     []shared.Output
	OutputChain, BodyChain, RecipientKeyChain frontend.Variable
	nullifierPks                              []frontend.Variable
	slotBytes                                 [][]frontend.Variable
}

type delivery struct {
	shared.Output
	// bodyHash is hash_bytes(body), zero on an exit.
	bodyHash frontend.Variable
	amount   []frontend.Variable
}

// Deliver opens every slot, proves each ring output body for the holder of its recipient key and pins each blinding and the exits flag.
func (w AuditWires) Deliver(api frontend.API, rc frontend.Rangechecker, e Envelope, layout Layout, outputs []DeliveryWires) Delivered {
	var hashes, bodyHashes, recipientKeys, nullifierPks []frontend.Variable
	slots := make([]shared.Output, len(outputs))
	slotBytes := make([][]frontend.Variable, len(outputs))
	for i, output := range outputs {
		// 1. Every ring output body opens for the holder of its published recipient key.
		slots[i] = OpenOutput(api, output.Output)
		d := w.deliver(api, rc, e, output, slots[i], recipientKey(api, slots[i], output.RecipientKey), i)
		// 2. The auditor rebuilds every blinding from tx_viewing_sk, no UTXO carries ring data.
		w.AssertBlinding(api, e, slots[i], i)
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slots[i].Utxo, V: slots[i].RingDataHash})
		hashes, bodyHashes = append(hashes, d.Hash), append(bodyHashes, d.bodyHash)
		// 3. The program rebuilds the owner tag from the published key, a ring output's key bytes are the ones ECDH bounds.
		key, notExit := shared.PackBounded(api, output.RecipientKey[:]), api.Sub(1, slots[i].Exit)
		recipientKeys = append(recipientKeys, api.Mul(notExit, key[0]), api.Mul(notExit, key[1]))
		nullifierPks = append(nullifierPks, api.Mul(slots[i].Utxo, slots[i].NullifierPk))
		slotBytes[i] = slotDisclosure(api, rc, output, d, shared.Zeros(8))
	}
	// 4. SeedOut and the exit bytes of every slot appear exactly when a UTXO exits.
	layout.AssertExits(api, slots)
	return Delivered{
		Slots:             slots,
		OutputChain:       gadget.HashChain4(api, hashes),
		BodyChain:         gadget.HashChain4(api, bodyHashes),
		RecipientKeyChain: gadget.HashChain4(api, recipientKeys),
		nullifierPks:      nullifierPks,
		slotBytes:         slotBytes,
	}
}

// Disclosure is the delivered disclosure the layout flags select, mirrored by DisclosureLayout::Delivered in program-libs/interface/src/proof/disclosure.rs.
//
//	SeedOut under LayoutExits, nullifier_pk per slot unless LayoutEscrow,
//	pack_disclosure(slot bytes per slot), 40 bytes under LayoutExits and the first 32 otherwise
func (d Delivered) Disclosure(api frontend.API, e Envelope, layout Layout) frontend.Variable {
	var wideBytes, denseBytes []frontend.Variable
	for _, bytes := range d.slotBytes {
		// Without an exit every dropped tail byte is zero, a ring output's tail and a dummy slot alike.
		wideBytes, denseBytes = append(wideBytes, bytes...), append(denseBytes, bytes[:32]...)
	}
	wide, dense := shared.PackDisclosure(api, wideBytes), shared.PackDisclosure(api, denseBytes)
	return e.disclose(api, layout.choices(api, LayoutExits|LayoutEscrow), func(choice layoutChoice) disclosureLayout {
		keys, slots := d.nullifierPks, dense
		if choice.has(LayoutEscrow) {
			keys = nil
		}
		if choice.has(LayoutExits) {
			slots = wide
		}
		return choice.fixed(slices.Concat(e.seedOut(choice), keys, slots))
	})
}

func recipientKey(api frontend.API, slot shared.Output, key [32]frontend.Variable) [32]frontend.Variable {
	var u [32]frontend.Variable
	for j := range u {
		// A slot without a recipient agrees with the base point, the ladder stays satisfiable on every slot.
		u[j] = api.Select(slot.Ring, key[j], basepointByte(j))
	}
	return u
}

// deliver proves a ring output's body opens to its committed blinding and amount for the holder of u.
func (w AuditWires) deliver(api frontend.API, rc frontend.Rangechecker, e Envelope, d DeliveryWires, slot shared.Output, u [32]frontend.Variable, i int) delivery {
	// 1. One encoding per recipient key, an alias would key the slot secret and the owner tag to bytes the recipient never derives.
	agreement := shared.AgreeCanonical(api, e.txViewingSk, u)
	// 2. be32 is the one encoding below q, the recipient decodes the committed blinding.
	blinding := ringgadget.FieldToBytesBEWith(api, rc, slot.Blinding)
	// 3. The agreement's ECDH bounds every byte of u and returns canonical agreement bytes.
	recipient := [2]frontend.Variable(shared.PackBounded(api, shared.Tagged(u)))
	// 4. The slot secret binds the agreement, both keys, the salt, the slot and n0, no two slots share a keystream.
	secret := shared.DeliveredSlot{
		Agreement:      [2]frontend.Variable(shared.PackBounded(api, agreement[:])),
		TxPk:           e.txPk,
		Recipient:      recipient,
		Salt:           e.salt,
		OutputIndex:    i,
		FirstNullifier: w.FirstNullifier,
	}.Secret(api)
	key, nonce := shared.AuditStreamKeySchedule(api, secret)
	// 5. A ring output's body is the encryption of its opening, the recipient and the auditor decrypt the same bytes.
	amount := ringgadget.UintBytesBE(api, slot.Amount, 8)
	for j, b := range aes.NewCipher(api, key).CTREncrypt(nonce, slices.Concat(blinding[:], amount)) {
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: d.Body[j], B: b})
	}
	// 6. A ring output's owner is the identity of the key the disclosure names.
	assertOwnerKey(api, slot, d.OwnerKey)
	return delivery{
		Output: slot,
		// A ring output's body bytes are the cipher's bounded bytes, a dummy's random body binds nothing else.
		bodyHash: api.Mul(api.Sub(1, slot.Exit), gadget.HashBoundedBytes(api, d.Body[:])),
		amount:   amount,
	}
}

// slotDisclosure is owner_key ‖ ringTail on a ring output, asset ‖ u64be(amount) zero padded to its width on an exit.
func slotDisclosure(api frontend.API, rc frontend.Rangechecker, o DeliveryWires, d delivery, ringTail []frontend.Variable) []frontend.Variable {
	bytes := slices.Concat(masked(api, d.Ring, o.OwnerKey[:]), masked(api, d.Ring, ringTail))
	// An exit discloses its asset as the one 32-byte encoding below q.
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(d.Exit, d.Asset))
	exit := slices.Concat(asset[:], masked(api, d.Exit, d.amount))
	for j, b := range exit {
		// A ring output and an exit exclude each other, so every byte holds one layout.
		bytes[j] = api.Add(bytes[j], b)
	}
	return bytes
}

func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
