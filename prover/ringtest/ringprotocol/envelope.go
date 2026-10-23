package ringprotocol

import (
	stdaes "crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// SealBody is the delivered body, AES-256-CTR of asset_address ‖ u64be(amount) under the stream of the slot secret.
func SealBody(t testing.TB, slotSecret *big.Int, assetAddress [32]byte, amount uint64) [shared.BodyLen]byte {
	t.Helper()
	plaintext := binary.BigEndian.AppendUint64(append([]byte{}, assetAddress[:]...), amount)
	key, nonce := AuditStreamKeys(t, slotSecret)
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

// XPublicKey is the X25519 u of scalar.
func XPublicKey(t testing.TB, scalar [32]byte) [32]byte {
	t.Helper()
	return [32]byte(XPrivateKey(t, scalar).PublicKey().Bytes())
}

// Tagged is the 0x04 || u encoding of an X25519 key.
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
func AuditStreamKeys(t testing.TB, secret *big.Int) (key [32]byte, nonce [12]byte) {
	t.Helper()
	head := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, new(big.Int).SetBytes(append([]byte(shared.AuditEncInfo), 0)), secret))
	tail := spptest.MustFieldBytes(t, ringtest.MustPoseidonHash(t, new(big.Int).SetBytes(append([]byte(shared.AuditEncInfo), 1)), secret))
	copy(key[:31], head[1:])
	key[31] = tail[19]
	copy(nonce[:], tail[20:])
	return key, nonce
}

// CTREncrypt mirrors aes.Cipher.CTREncrypt, the first keystream block counts from nonce || 2.
func CTREncrypt(t testing.TB, key [32]byte, nonce [12]byte, plaintext []byte) []byte {
	t.Helper()
	block, err := stdaes.NewCipher(key[:])
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	var counter [16]byte
	copy(counter[:12], nonce[:])
	counter[15] = 2

	ciphertext := make([]byte, len(plaintext))
	cipher.NewCTR(block, counter[:]).XORKeyStream(ciphertext, plaintext)
	return ciphertext
}

func Tag(value uint32) *big.Int {
	return new(big.Int).SetUint64(uint64(value))
}
