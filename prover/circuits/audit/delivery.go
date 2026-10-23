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

type DeliveryWires struct {
	Output shared.UtxoWires
	// AssetAddress is the mint the body opens with, all zero for SOL.
	AssetAddress [32]frontend.Variable
	// RecipientKey is the X25519 u the body is sealed to.
	RecipientKey [32]frontend.Variable
	OwnerKey     [32]frontend.Variable
	Body         [shared.BodyLen]frontend.Variable
}

type delivery struct {
	outputSlot
	// secret is the CRDS slot secret the recipient rebuilds from its own key.
	secret frontend.Variable
	// recipient is pack_be(0x04 ‖ u) of the key the slot agreed with, the base point off a ring output.
	recipient [2]frontend.Variable
	// bodyHash is hash_bytes(body), zero on an exit.
	bodyHash frontend.Variable
	amount   []frontend.Variable
}

// openDelivered classifies every UTXO of a delivered rail as a ring output or an exit.
func openDelivered(api frontend.API, d DeliveryWires) outputSlot {
	opened := d.Output.Open(api)
	slot := classify(api, d.Output, opened, opened.Utxo)
	// The recipient rebuilds the whole commitment from the body and its own keys, no UTXO carries output data.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: d.Output.DataHash})
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: d.Output.RingDataHash})
	return slot
}

// recipientKey is the key a slot agrees with, RecipientKey on a ring output and the base point on any other slot.
func recipientKey(api frontend.API, slot outputSlot, key [32]frontend.Variable) [32]frontend.Variable {
	var u [32]frontend.Variable
	for j := range u {
		// A slot without a recipient agrees with the base point, a gated key could still leave the ladder unsatisfiable.
		u[j] = api.Select(slot.ring, key[j], basepointByte(j))
	}
	return u
}

// deliver proves a ring output's body opens to its committed asset and amount for the holder of u.
func (w AuditWires) deliver(api frontend.API, e auditEnvelope, d DeliveryWires, slot outputSlot, u [32]frontend.Variable, i int) delivery {
	// 1. One encoding per recipient key, an alias would key the slot secret and the owner tag or inbox key to bytes the recipient never derives.
	agreement := shared.AgreeCanonical(api, e.txViewingSk, u)
	// 2. The committed asset is hash_bytes of the mint the body names, the cipher's byte tables bound the mint bytes.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.ring, A: d.Output.Asset, B: gadget.HashBoundedBytes(api, d.AssetAddress[:])})
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
	amount := uintBytes(api, d.Output.Amount, 8)
	for j, b := range aes.NewCipher(api, key).CTREncrypt(nonce, slices.Concat(d.AssetAddress[:], amount)) {
		// 5. A ring output's body is the encryption of its opening, the recipient and the auditor decrypt the same bytes.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.ring, A: d.Body[j], B: b})
	}
	// 6. A ring output's owner is the identity of the key the disclosure names.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.ring, A: d.Output.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, d.OwnerKey)})
	return delivery{
		outputSlot: slot,
		secret:     secret,
		recipient:  recipient,
		// A ring output's body bytes are the cipher's bounded bytes, a dummy's random body binds nothing else.
		bodyHash: api.Mul(api.Sub(1, slot.exit), gadget.HashBoundedBytes(api, d.Body[:])),
		amount:   amount,
	}
}

// slotDisclosure is owner_key ‖ ringTail on a ring output, asset ‖ u64be(amount) zero padded to its width on an exit.
func slotDisclosure(api frontend.API, rc frontend.Rangechecker, o DeliveryWires, d delivery, ringTail []frontend.Variable) []frontend.Variable {
	bytes := slices.Concat(masked(api, d.ring, o.OwnerKey[:]), masked(api, d.ring, ringTail))
	asset := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(d.exit, o.Output.Asset))
	exit := slices.Concat(asset[:], masked(api, d.exit, d.amount))
	for j, b := range exit {
		// A ring output and an exit exclude each other, so every byte holds one layout.
		bytes[j] = api.Add(bytes[j], b)
	}
	return bytes
}

// basepointByte is byte j of the X25519 base point u = 9.
func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
