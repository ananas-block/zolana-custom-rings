// Holds what every auditor proof shares. The auditor receives one secret per
// transfer and opens every note and disclosure of the transfer with it, and
// each proof matches exactly one shielded pool transfer.
//
// Read after shared/envelope.go, shared/derivation.go, shared/utxo.go. Read
// before audit/layout.go, audit/delivered.go, audit/anonymous.go, transfer/transfer.go.

// Package audit proves what a ring auditor reads from a ring transfer.
package audit

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// AnonymousAuditShape sizes the anonymous section, FullOpenings the entry layout of a spend of default-ring notes.
type AnonymousAuditShape struct {
	InputClass   int
	Outputs      int
	FullOpenings bool
}

type AuditWires struct {
	FirstNullifier frontend.Variable
	// RingProgramID is hash_bytes(ring program address), the id SPP binds every ring output to.
	RingProgramID frontend.Variable
	TxViewingSk   [32]frontend.Variable
	EphSk         [32]frontend.Variable
	AuditorPk     [32]frontend.Variable
	Salt          [16]frontend.Variable
	Layout        frontend.Variable
}

// Envelope is one transfer's opened auditor envelope.
type Envelope struct {
	txViewingSk [32]frontend.Variable
	// txPk is pack_be(0x04 ‖ tx_u).
	txPk [2]frontend.Variable
	// packedTxViewingSk is pack_be(tx_viewing_sk), the key of the CRBS blinding seed and the CROD pad.
	packedTxViewingSk [2]frontend.Variable
	salt              frontend.Variable
	outputSeed        frontend.Variable
	sealedFields      []frontend.Variable
}

// Seal binds tx_viewing_sk to its tagged public key and seals it to the auditor.
func (w AuditWires) Seal(api frontend.API, rc frontend.Rangechecker) Envelope {
	// 1. The salt is 16 bytes, one field below 2^128 the program rebuilds from the instruction.
	salt := gadget.BytesToFieldWith(api, rc, w.Salt[:])
	// 2. The auditor reads the recovered bytes as they are, an unclamped alias would key another stream.
	AssertClamped(api, w.TxViewingSk)
	// 3. tx_u is the key of tx_viewing_sk, the generator bounds every secret byte the packings read.
	txPk := shared.PackBounded(api, TaggedPubkey(api, w.TxViewingSk))
	// 4. The envelope seals tx_viewing_sk to the auditor under the audit stream schedule.
	sealed := shared.Envelope{Plaintext: w.TxViewingSk[:], EphSk: w.EphSk, AuditorPk: w.AuditorPk}.SealAuditStream(api)
	packedTxViewingSk := [2]frontend.Variable(shared.PackBounded(api, w.TxViewingSk[:]))
	return Envelope{
		txViewingSk:       w.TxViewingSk,
		txPk:              [2]frontend.Variable(txPk),
		packedTxViewingSk: packedTxViewingSk,
		salt:              salt,
		outputSeed:        transaction.DeriveOutputBlindingSeed(api, w.FirstNullifier, shared.BlindingSeed(api, packedTxViewingSk, salt)),
		sealedFields:      sealed.StatementFields(api),
	}
}

// OpenOutput opens an output slot the auditor reads, no UTXO carries a data hash the recipient never learns.
func OpenOutput(api frontend.API, o shared.UtxoWires) shared.Output {
	opened := o.Open(api)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: opened.Utxo, V: o.DataHash})
	return opened
}

func assertOwnerKey(api frontend.API, slot shared.Output, key [32]frontend.Variable) {
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Ring, A: slot.OwnerPkHash, B: gadget.SolanaOwnerIdentity(api, key)})
}

// AssertBlinding pins a live UTXO's blinding to SPP's TXOB blinding over the seed tx_viewing_sk fixes.
func (w AuditWires) AssertBlinding(api frontend.API, e Envelope, slot shared.Output, i int) {
	blinding := transaction.DeriveOutputBlinding(api, w.FirstNullifier, e.outputSeed, i)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: slot.Utxo, A: slot.Blinding, B: blinding})
}

// Head opens every audit statement under domain, mirrored by AuditHead in program-libs/interface/src/proof/statement.rs.
//
//	domain, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout
func (e Envelope) Head(w AuditWires, domain frontend.Variable) []frontend.Variable {
	return slices.Concat(
		[]frontend.Variable{domain, w.FirstNullifier, w.RingProgramID, e.txPk[0], e.txPk[1]},
		e.sealedFields,
		[]frontend.Variable{e.salt, w.Layout},
	)
}

// SpentBySender holds every input slot to the sender while live, slot 0 to a UTXO while required, and returns utxo * hash per slot.
func SpentBySender(api frontend.API, inputs []shared.UtxoWires, live, required, sender frontend.Variable) []frontend.Variable {
	hashes := make([]frontend.Variable, len(inputs))
	for i, input := range inputs {
		_, hashes[i] = spentBySender(api, input, live, required, sender, i)
	}
	return hashes
}

// AssertClamped pins the RFC 7748 clamped encoding, the one byte string per X25519 key.
func AssertClamped(api frontend.API, secret [32]frontend.Variable) {
	low := api.ToBinary(secret[0], 8)
	high := api.ToBinary(secret[31], 8)
	// Bits 0 to 2 are clear, the scalar is a multiple of the cofactor.
	for _, bit := range low[:3] {
		api.AssertIsEqual(bit, 0)
	}
	// Bit 254 is set and bit 255 is clear, the top RFC 7748 fixes.
	api.AssertIsEqual(high[6], 1)
	api.AssertIsEqual(high[7], 0)
}

// TaggedPubkey is 0x04 ‖ u of the clamped secret, the generator gadget bounds every secret byte.
func TaggedPubkey(api frontend.API, secret [32]frontend.Variable) []frontend.Variable {
	return shared.Tagged(x25519.ScalarMulGenerator(api, secret))
}

func masked(api frontend.API, flag frontend.Variable, bytes []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(bytes))
	for i, b := range bytes {
		out[i] = api.Mul(flag, b)
	}
	return out
}
