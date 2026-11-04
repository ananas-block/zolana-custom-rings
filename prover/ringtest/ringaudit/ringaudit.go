// Package ringaudit recomputes the audit statements of package audit on the host.
package ringaudit

import (
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
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

func AuditorSk() [32]byte { return ringtest.Scalar(0x33) }

func DefaultKeys(t testing.TB) Keys {
	t.Helper()
	txViewingSk := ringprotocol.Clamped(ringtest.Scalar(0x11))
	ephSk := ringtest.Scalar(0x22)
	txPriv := ringprotocol.XPrivateKey(t, txViewingSk)
	ephPriv := ringprotocol.XPrivateKey(t, ephSk)
	auditorPriv := ringprotocol.XPrivateKey(t, AuditorSk())

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

func (k Keys) EphPk() [33]byte {
	return k.ephPk
}

type Sealed struct {
	AuditorLo      *big.Int
	AuditorHi      *big.Int
	EphLo          *big.Int
	EphHi          *big.Int
	CiphertextHash *big.Int
}

// Seal mirrors shared.Envelope.Seal, the merge envelope.
func (k Keys) Seal(t testing.TB, plaintext []byte, info string) Sealed {
	t.Helper()
	return k.Sealed(t, k.EnvelopeCiphertext(t, plaintext, info))
}

func (k Keys) EnvelopeCiphertext(t testing.TB, plaintext []byte, info string) []byte {
	t.Helper()
	key, nonce := ringprotocol.KeySchedule(t, k.envelopeSecret(t), info)
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

func (k Keys) SealStream(t testing.TB, plaintext []byte, label string) Sealed {
	t.Helper()
	return k.Sealed(t, k.StreamCiphertext(t, plaintext, label))
}

func (k Keys) StreamCiphertext(t testing.TB, plaintext []byte, label string) []byte {
	t.Helper()
	key, nonce := ringprotocol.AuditStreamKeys(t, k.envelopeSecret(t), label)
	return ringprotocol.CTREncrypt(t, key, nonce, plaintext)
}

func (k Keys) AuditHead(t testing.TB, firstNullifier, ringID *big.Int, salt [16]byte, envelope []byte) AuditHead {
	t.Helper()
	return AuditHead{
		FirstNullifier: firstNullifier,
		RingProgramID:  ringID,
		TxViewingU:     [32]byte(k.txPk[1:]),
		AuditorPubkey:  ringprotocol.Tagged(k.auditorPk[:]),
		EphU:           [32]byte(k.ephPk[1:]),
		Envelope:       envelope,
		Salt:           salt,
	}
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

// Stream is the auditor keystream's ciphertext over every region of a key.
type Stream struct {
	Ranges     audit.StreamRanges
	Ciphertext []byte
}

// SealAuditorStream mirrors audit.AuditWires.SealStream, a region the key lacks stays empty.
func (k Keys) SealAuditorStream(t testing.TB, ranges audit.StreamRanges, envelope []byte, records, tails [][]byte) Stream {
	t.Helper()
	plaintext := append(slices.Clone(envelope), make([]byte, ranges.RecordOffset(0)-len(envelope))...)
	plaintext = append(plaintext, slices.Concat(records...)...)
	plaintext = append(plaintext, slices.Concat(tails...)...)
	return Stream{Ranges: ranges, Ciphertext: k.StreamCiphertext(t, plaintext, shared.AuditEncInfo)}
}

// Open decrypts a stream the auditor read, the keystream is the zero plaintext's ciphertext.
func (k Keys) Open(t testing.TB, stream Stream) []byte {
	t.Helper()
	keystream := k.StreamCiphertext(t, make([]byte, len(stream.Ciphertext)), shared.AuditEncInfo)
	plaintext := make([]byte, len(keystream))
	for i := range plaintext {
		plaintext[i] = keystream[i] ^ stream.Ciphertext[i]
	}
	return plaintext
}

func (s Stream) Envelope(count int) []byte {
	return s.Ciphertext[:s.Ranges.EnvelopeLen(count)]
}

func (s Stream) Record(i int) []byte {
	offset := s.Ranges.RecordOffset(i)
	return s.Ciphertext[offset : offset+audit.RecordLen]
}

func (s Stream) Tail(i int) []byte {
	offset := s.Ranges.TailOffset(i)
	return s.Ciphertext[offset : offset+audit.TailLen]
}
