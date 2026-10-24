// Package ringaudit recomputes the audit statements of package audit on the host.
package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
)

// Keys are the envelope keys of one audited transfer.
type Keys struct {
	txViewingSk [32]byte
	ephSk       [32]byte
	txPk        [33]byte
	ephPk       [33]byte
	auditorPk   [32]byte
	dh          [32]byte
}

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txViewingSk := ringprotocol.Clamped(ringtest.Scalar(0x11))
	ephSk := ringtest.Scalar(0x22)
	txPriv := ringprotocol.XPrivateKey(t, txViewingSk)
	ephPriv := ringprotocol.XPrivateKey(t, ephSk)
	auditorPriv := ringprotocol.XPrivateKey(t, ringtest.Scalar(0x33))

	dh, err := ephPriv.ECDH(auditorPriv.PublicKey())
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	return Keys{
		txViewingSk: txViewingSk,
		ephSk:       ephSk,
		txPk:        ringprotocol.Tagged(txPriv.PublicKey().Bytes()),
		ephPk:       ringprotocol.Tagged(ephPriv.PublicKey().Bytes()),
		auditorPk:   [32]byte(auditorPriv.PublicKey().Bytes()),
		dh:          [32]byte(dh),
	}
}

// WithRawTxScalar witnesses secret unclamped under the key its clamping publishes.
func (k Keys) WithRawTxScalar(t testing.TB, secret [32]byte) Keys {
	t.Helper()
	k.txPk = ringprotocol.Tagged(ringprotocol.XPrivateKey(t, ringprotocol.Clamped(secret)).PublicKey().Bytes())
	k.txViewingSk = secret
	return k
}

func (k Keys) TxViewingSk() [32]byte {
	return k.txViewingSk
}

func (k Keys) EphSk() [32]byte {
	return k.ephSk
}

func (k Keys) AuditorPk() [32]byte {
	return k.auditorPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

// Seal mirrors shared.Envelope.Seal under the key schedule of info.
func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	return k.Sealed(t, k.EnvelopeCiphertext(t, plaintext, info))
}

func (k Keys) EnvelopeCiphertext(t testing.TB, plaintext []byte, info string) []byte {
	t.Helper()
	key, nonce := ringprotocol.KeySchedule(t, k.envelopeSecret(t), info)
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

// SealAuditStream mirrors shared.Envelope.SealAuditStream.
func (k Keys) SealAuditStream(t testing.TB, plaintext []byte) Sealed {
	t.Helper()
	return k.Sealed(t, k.auditStreamCiphertext(t, plaintext))
}

// AuditHead is the statement head of a transfer sealing the transaction viewing key under the audit stream.
func (k Keys) AuditHead(t testing.TB, firstNullifier, ringID *big.Int, salt [16]byte) AuditHead {
	t.Helper()
	return AuditHead{
		FirstNullifier: firstNullifier,
		RingProgramID:  ringID,
		TxViewingU:     [32]byte(k.txPk[1:]),
		AuditorPubkey:  ringprotocol.Tagged(k.auditorPk[:]),
		EphU:           [32]byte(k.ephPk[1:]),
		Sealed:         k.auditStreamCiphertext(t, k.txViewingSk[:]),
		Salt:           salt,
	}
}

func (k Keys) auditStreamCiphertext(t testing.TB, plaintext []byte) []byte {
	t.Helper()
	key, nonce := ringprotocol.AuditStreamKeys(t, k.envelopeSecret(t))
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

// Disclose adds the CROD pad of the transaction key and salt to every field.
func (k Keys) Disclose(t testing.TB, salt [16]byte, fields []*big.Int) []*big.Int {
	t.Helper()
	return ringprotocol.Disclose(t, shared.DisclosurePadDomain, k.txViewingSk, salt, fields)
}

// envelopeSecret is Poseidon(CR_S, pack_be(dh), pack_be(eph), pack_be(auditor)) of the envelope.
func (k Keys) envelopeSecret(t testing.TB) *big.Int {
	t.Helper()
	dhLo, dhHi := ringprotocol.Pack32(k.dh)
	ephLo, ephHi := ringprotocol.Pack33(k.ephPk)
	auditorLo, auditorHi := ringprotocol.Pack33(ringprotocol.Tagged(k.auditorPk[:]))
	return ringtest.MustPoseidonHash(t, ringprotocol.Tag(shared.DomSepCRShared), dhLo, dhHi, ephLo, ephHi, auditorLo, auditorHi)
}

func (k Keys) Sealed(t testing.TB, ciphertext []byte) Sealed {
	t.Helper()
	ephLo, ephHi := ringprotocol.Pack33(k.ephPk)
	auditorLo, auditorHi := ringprotocol.Pack33(ringprotocol.Tagged(k.auditorPk[:]))
	return Sealed{
		AuditorLo:      auditorLo,
		AuditorHi:      auditorHi,
		EphLo:          ephLo,
		EphHi:          ephHi,
		CiphertextHash: ringtest.HashBytes(t, ciphertext),
	}
}
