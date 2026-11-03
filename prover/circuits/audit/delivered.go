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
// 2. The output chain covers every published slot.
// 3. Every UTXO is a ring output or an exit and carries no output data.

type DeliveryWires struct {
	Output shared.UtxoWires
	// RecipientKey is the X25519 u the body is sealed to.
	RecipientKey [32]frontend.Variable
	OwnerKey     [32]frontend.Variable
	// Body past EscrowBodyLen reaches neither the equality nor the selected hash under LayoutEscrow.
	Body [shared.BodyLen]frontend.Variable
}

func (d DeliveryWires) utxoWires() shared.UtxoWires { return d.Output }

type Delivered struct {
	OutputCiphertextChain, RecipientKeyChain frontend.Variable
}

// ExitRecords returns one record per slot, only an exit's region leaves the stream.
func (o Opened) ExitRecords() [][]frontend.Variable {
	records := make([][]frontend.Variable, len(o.bytes))
	for i, bytes := range o.bytes {
		records[i] = bytes.exitRecord()
	}
	return records
}

func (w AuditWires) Deliver(api frontend.API, e Envelope, keyEscrow frontend.Variable, outputs []DeliveryWires, opened Opened, stream Stream) Delivered {
	var ciphertexts, recipientKeys []frontend.Variable
	for i, output := range outputs {
		slot := opened.Slots[i]
		// 1. Every ring output body opens for the holder of its published recipient key.
		w.deliver(api, e, keyEscrow, output, slot, opened.bytes[i], i)
		// Each slot chains the one ciphertext the program hashes from the frame.
		active := opened.Count.Active[i]
		ciphertexts = append(ciphertexts, api.Mul(active, slotCiphertextHash(api, keyEscrow, output, slot, stream.record(i))))
		// The program rebuilds the owner tag from the published key, zero on an exit and past the published count.
		recipientKeys = append(recipientKeys, recipientKeyFields(api, output, slot, active)...)
	}
	return Delivered{
		OutputCiphertextChain: gadget.HashChain4(api, ciphertexts),
		RecipientKeyChain:     gadget.HashChain4(api, recipientKeys),
	}
}

// slotCiphertextHash mirrors slot_ciphertext_hash in program-libs/interface/src/proof/statement.rs.
func slotCiphertextHash(api frontend.API, keyEscrow frontend.Variable, d DeliveryWires, slot shared.Output, record []frontend.Variable) frontend.Variable {
	body := api.Select(keyEscrow, gadget.HashBoundedBytes(api, d.Body[:shared.EscrowBodyLen]), gadget.HashBoundedBytes(api, d.Body[:]))
	exit := api.Select(keyEscrow, gadget.HashBoundedBytes(api, record[:EscrowExitRecordLen]), gadget.HashBoundedBytes(api, record[:ExitRecordLen]))
	return api.Select(slot.Exit, exit, body)
}

// recipientKeyFields masks an exit's key, the agreement's ECDH bounds a ring output's bytes.
func recipientKeyFields(api frontend.API, d DeliveryWires, slot shared.Output, active frontend.Variable) []frontend.Variable {
	key, published := shared.PackBounded(api, d.RecipientKey[:]), api.Sub(active, slot.Exit)
	return []frontend.Variable{api.Mul(published, key[0]), api.Mul(published, key[1])}
}

func recipientKey(api frontend.API, live frontend.Variable, key [32]frontend.Variable) [32]frontend.Variable {
	var u [32]frontend.Variable
	for j := range u {
		// A slot without a recipient agrees with the base point, the ladder stays satisfiable on every slot.
		u[j] = api.Select(live, key[j], basepointByte(j))
	}
	return u
}

// slotSecret is the CRDS secret of index under u, an alias of u would key it to bytes the holder never derives.
func (w AuditWires) slotSecret(api frontend.API, e Envelope, u [32]frontend.Variable, index frontend.Variable) frontend.Variable {
	agreement := shared.AgreeCanonical(api, e.txViewingSk, u)
	// The agreement's ECDH bounds every byte of u and returns canonical agreement bytes.
	recipient := [2]frontend.Variable(shared.PackBounded(api, shared.Tagged(u)))
	// The index and n0 in the secret keep two slots off one keystream.
	return shared.DeliveredSlot{
		Agreement:      [2]frontend.Variable(shared.PackBounded(api, agreement[:])),
		TxPk:           e.txPk,
		Recipient:      recipient,
		Salt:           e.salt,
		OutputIndex:    index,
		FirstNullifier: w.FirstNullifier,
	}.Secret(api)
}

// deliver mirrors DeliveredBody::encode in program-libs/interface/src/proof/audit_stream.rs, key escrow cuts the last field.
func (w AuditWires) deliver(api frontend.API, e Envelope, keyEscrow frontend.Variable, d DeliveryWires, slot shared.Output, bytes slotBytes, i int) {
	secret := w.slotSecret(api, e, recipientKey(api, slot.Ring, d.RecipientKey), i)
	// The CRING/bdy1 label separates a body's key from every other line over one secret.
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
	// A ring output's owner is the identity of the key the body names, a recipient compares it with its own.
	assertOwnerKey(api, slot, d.OwnerKey)
	// A body names no asset, a nonzero amount leaves balance tying it to a settled mint the auditor can try.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Ring, V: api.IsZero(slot.Amount)})
}

func basepointByte(j int) frontend.Variable {
	if j == 0 {
		return 9
	}
	return 0
}
