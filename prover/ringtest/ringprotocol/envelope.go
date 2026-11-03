package ringprotocol

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	ve "github.com/helius-labs/zolana/prover/server/circuits/encryption"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type Body struct {
	Blinding    *big.Int
	Amount      uint64
	OwnerKey    [32]byte
	NullifierPk *big.Int
}

func (b Body) Seal(t testing.TB, slotSecret *big.Int) [shared.BodyLen]byte {
	t.Helper()
	blinding, nullifierPk := spptest.MustFieldBytes(t, b.Blinding), spptest.MustFieldBytes(t, b.NullifierPk)
	plaintext := slices.Concat(blinding[:], binary.BigEndian.AppendUint64(nil, b.Amount), b.OwnerKey[:], nullifierPk[:])
	key, nonce := AuditStreamKeys(t, slotSecret, shared.BodyEncInfo)
	return [shared.BodyLen]byte(CTREncrypt(t, key, nonce, plaintext))
}

// Clamped is the RFC 7748 clamping of secret, the one encoding the circuit accepts as plaintext.
func Clamped(secret [32]byte) [32]byte {
	secret[0] &= 248
	secret[31] = (secret[31] & 127) | 64
	return secret
}

func XPrivateKey(t testing.TB, scalar [32]byte) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.X25519().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func XPublicKey(t testing.TB, scalar [32]byte) [32]byte {
	t.Helper()
	return [32]byte(XPrivateKey(t, scalar).PublicKey().Bytes())
}

func Tagged(key []byte) [33]byte {
	var out [33]byte
	out[0] = 4
	copy(out[1:], key)
	return out
}

// Pack32 mirrors gadget.PackBytesBE over 32 bytes.
func Pack32(bytes [32]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(bytes[:31]), new(big.Int).SetUint64(uint64(bytes[31]))
}

// Pack33 mirrors gadget.PackBytesBE over 33 bytes.
func Pack33(key [33]byte) (lo, hi *big.Int) {
	return new(big.Int).SetBytes(key[:31]), new(big.Int).SetUint64(uint64(key[31])<<8 | uint64(key[32]))
}

// AuditStreamKeys mirrors shared.AuditStreamKeySchedule.
func AuditStreamKeys(t testing.TB, secret *big.Int, label string) (key [32]byte, nonce [12]byte) {
	t.Helper()
	head := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, new(big.Int).SetBytes(append([]byte(label), 0)), secret))
	tail := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, new(big.Int).SetBytes(append([]byte(label), 1)), secret))
	copy(key[:31], head[1:])
	key[31] = tail[19]
	copy(nonce[:], tail[20:])
	return key, nonce
}

// EnvelopeDigest mirrors ciphertext_digest, head element 9 of a transfer statement.
func EnvelopeDigest(t testing.TB, ciphertext []byte) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(int64(len(ciphertext))), spptest.MustHashChain4(t, PackDisclosure(ciphertext)))
}

// KeySchedule mirrors ve.KeySchedule for an info string of at most 31 bytes.
func KeySchedule(t testing.TB, secret *big.Int, info string) (key [32]byte, nonce [12]byte) {
	t.Helper()
	if len(info) > 31 {
		t.Fatalf("info %q packs into more than one field", info)
	}
	siloed := ringtest.MustPoseidonHash(t, Tag(ve.DomSepSilo), secret, new(big.Int).SetBytes([]byte(info)))
	keyLo := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, Tag(ve.DomSepKey), siloed))
	keyHi := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, Tag(ve.DomSepKey+1), siloed))
	nonceRaw := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, Tag(ve.DomSepNonce), siloed))
	copy(key[:16], keyHi[16:])
	copy(key[16:], keyLo[16:])
	copy(nonce[:], nonceRaw[20:])
	return key, nonce
}

// CTREncrypt mirrors aes.Cipher.CTREncrypt, the first keystream block counts from nonce || 2.
func CTREncrypt(t testing.TB, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	return CTREncryptAt(t, key, nonce, 2, plaintext)
}

func CTREncryptAt(t testing.TB, key [32]byte, nonce [12]byte, first uint32, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	binary.BigEndian.PutUint32(counter[12:], first)

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func Tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}
