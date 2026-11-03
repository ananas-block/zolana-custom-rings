package audit_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

// The witness these bytes come from solves the key, a sealer or reader reaching them agrees with the proof.
func TestAnonymousBodiesVector(t *testing.T) {
	a := ringaudit.NewAnonymousAudit(t, deliveryShape)
	compileAnonymous(t, deliveryShape).RequireSolved(t, a.Circuit(t))
	txViewingSk := a.Keys.TxViewingSk()
	payment := a.Outputs[1]
	bundle := a.Bundle(t)
	// Fixture recipient 0 and the fixture sender, clamped so a reader that refuses a raw scalar still takes them.
	recipientSk, senderSk := ringprotocol.Clamped(ringtest.Scalar(0x55)), ringprotocol.Clamped(ringtest.Scalar(0x77))
	if ringprotocol.XPublicKey(t, recipientSk) != payment.RecipientKey || ringprotocol.XPublicKey(t, senderSk) != a.SenderViewingKey {
		t.Fatal("a pinned viewing secret is not the fixture's")
	}
	ringtest.PinVector(t, "audit/anonymous_bodies.json", map[string]any{
		"description":          "One scheme 11 body and one scheme 12 bundle of an honest 4 slot frame, change in slot 0, payments in slots 1 and 3, an exit in slot 2. Body plaintext be32(blinding) || u64be(amount) || mint under label CRING/rcp1 and the CRDS slot secret of recipient_key and index. Bundle plaintext mint0 || u64be(amount0) || u64be(amount1) || output_seed || recipient_u * m under label CRING/snd1 and the CRDS slot secret of sender_viewing_key and index m, recipient_u zero on change and exit. bundle_digest = ciphertext_digest(bundle). body_tag = Poseidon(CRRT, body_slot_secret), bundle_tag = Poseidon(CRST, bundle_slot_secret), dummy_tag = Poseidon(CRRT, dummy_tag_preimage). Produced by prover/circuits/audit/delivery_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"tx_viewing_sk":        hex.EncodeToString(txViewingSk[:]),
		"salt":                 hex.EncodeToString(a.Salt[:]),
		"first_nullifier":      ringtest.FieldHex(a.FirstNullifier),
		"output_count":         a.OutputCount(),
		"output_seed":          ringtest.FieldHex(a.SeedOut),
		"sender_viewing_key":   hex.EncodeToString(a.SenderViewingKey[:]),
		"change_amount":        a.Outputs[0].Utxo.Amount,
		"change_mint":          hex.EncodeToString(a.Outputs[0].Mint[:]),
		"recipient_keys":       []string{"", hex.EncodeToString(payment.RecipientKey[:]), "", hex.EncodeToString(a.Outputs[3].RecipientKey[:])},
		"body_index":           1,
		"body_blinding":        ringtest.FieldHex(payment.Utxo.Blinding),
		"body_amount":          payment.Utxo.Amount,
		"body_mint":            hex.EncodeToString(payment.Mint[:]),
		"body_slot_secret":     ringtest.FieldHex(a.DeliveredSlotSecret(t, payment.RecipientKey, 1)),
		"body":                 hex.EncodeToString(payment.Body[:]),
		"bundle_slot_secret":   ringtest.FieldHex(a.DeliveredSlotSecret(t, a.SenderViewingKey, a.OutputCount())),
		"bundle":               hex.EncodeToString(bundle),
		"recipient_tag_domain": "43525254",
		"sender_tag_domain":    "43525354",
		"recipient_viewing_sk": hex.EncodeToString(recipientSk[:]),
		"sender_viewing_sk":    hex.EncodeToString(senderSk[:]),
		"body_tag":             ringtest.FieldHex(payment.Tag),
		"bundle_tag":           ringtest.FieldHex(a.BundleTag(t)),
		"dummy_tag_preimage":   "0000000000000000000000000000000000000000000000000000000000000d00",
		"dummy_tag":            ringtest.FieldHex(ringprotocol.RecipientTag(t, big.NewInt(0xd00))),
		"bundle_digest":        ringtest.FieldHex(ringprotocol.EnvelopeDigest(t, bundle)),
	})
}
