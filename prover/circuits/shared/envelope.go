// Proves that a ciphertext is encrypted to the ring's auditor key, so the
// auditor can always open what the proof binds. Each envelope needs a fresh
// one-time key, a reused key repeats the keystream.
//
// Read after shared/disclosure.go, ringgadget/bytes.go, shared/derivation.go.
// Read before audit/audit.go, deposit.go, merge.go.

package shared

import (
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/x25519"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// EphSk must be fresh per envelope or per SealSalted salt, a reuse under one auditor key repeats the keystream.
type Envelope struct {
	Plaintext []frontend.Variable
	EphSk     [32]frontend.Variable
	AuditorPk [32]frontend.Variable
	Info      string
}

// Every Ciphertext byte is bounded to 8 bits by the cipher's tables.
type Sealed struct {
	Auditor, Eph, Ciphertext []frontend.Variable
}

func (s Sealed) StatementFields(api frontend.API) []frontend.Variable {
	return append(slices.Concat(s.Auditor, s.Eph), gadget.HashBoundedBytes(api, s.Ciphertext))
}

// SealStream starts at counter 2, the readers start there.
func (e Envelope) SealStream(api frontend.API) Sealed {
	// The X25519 gadgets bound every key byte and return canonical bytes, the packings need no byte check.
	sealed, secret := e.agree(api, PackBounded(api, Tagged(x25519.ScalarMulGenerator(api, e.EphSk))))
	return e.seal(api, sealed, secret)
}

// SealSalted takes eph as the packed key of EphSk, a resend repeats EphSk and the salt keeps its keystream apart.
func (e Envelope) SealSalted(api frontend.API, eph []frontend.Variable, salt frontend.Variable) Sealed {
	sealed, secret := e.agree(api, eph)
	return e.seal(api, sealed, gadget.PoseidonHash(api, []frontend.Variable{secret, salt}))
}

func (e Envelope) agree(api frontend.API, eph []frontend.Variable) (Sealed, frontend.Variable) {
	// One encoding per auditor key, the program packs the configured key bytes as they are.
	agreement := AgreeCanonical(api, e.EphSk, e.AuditorPk)
	sealed := Sealed{Auditor: PackBounded(api, Tagged(e.AuditorPk)), Eph: eph}
	// Binding both keys keeps the key schedule input from replaying under another key pair.
	return sealed, gadget.PoseidonHash(api, slices.Concat(
		[]frontend.Variable{uint64(DomSepCRShared)}, PackBounded(api, agreement[:]), sealed.Eph, sealed.Auditor,
	))
}

func (e Envelope) seal(api frontend.API, sealed Sealed, secret frontend.Variable) Sealed {
	// The cipher's byte tables bound every plaintext byte.
	key, nonce := AuditStreamKeySchedule(api, secret, e.Info)
	sealed.Ciphertext = aes.NewCipher(api, key).CTREncrypt(nonce, e.Plaintext)
	return sealed
}

// AuditStreamKeySchedule mirrors RingStream::new in sdk-libs/keys/src/stream_cipher.rs, the label separates every ring line over one secret.
func AuditStreamKeySchedule(api frontend.API, secret frontend.Variable, label string) (key [32]frontend.Variable, nonce [12]frontend.Variable) {
	rc := rangecheck.New(api)
	tag := func(counter byte) *big.Int {
		return new(big.Int).SetBytes(append([]byte(label), counter))
	}
	head := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(0), secret}), 31)
	tail := gadget.FieldLowBytesBE(api, rc, gadget.PoseidonHash(api, []frontend.Variable{tag(1), secret}), 13)
	copy(key[:31], head)
	key[31] = tail[0]
	copy(nonce[:], tail[1:])
	return
}

// AgreeCanonical is X25519(scalar, peer) for a peer encoded below p = 2^255-19, one encoding per key.
func AgreeCanonical(api frontend.API, scalar, peer [32]frontend.Variable) [32]frontend.Variable {
	x25519.AssertCanonical(api, peer)
	return x25519.ECDH(api, scalar, peer)
}

func Tagged(u [32]frontend.Variable) []frontend.Variable {
	return append([]frontend.Variable{4}, u[:]...)
}
