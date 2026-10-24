package ringprotocol

import (
	"encoding/hex"
	"math/big"
	"testing"
)

func TestAuditStreamKDFVector(t *testing.T) {
	key, nonce := AuditStreamKeys(t, big.NewInt(0x12345))
	for _, vector := range []struct{ name, got, want string }{
		{"key", hex.EncodeToString(key[:]), "0b2e1ebe77448c2a18dc91fb208e751595208775296803011e0084baaf1bbb6d"},
		{"nonce", hex.EncodeToString(nonce[:]), "cc2327b19f62560112747d6f"},
		{"ciphertext", hex.EncodeToString(CTREncrypt(t, key, nonce, make([]byte, 32))), "001d45a89ea12a64c7e6886ce543a66f77971b2c1052688ff668fe8c0c5d7c7b"},
	} {
		if vector.got != vector.want {
			t.Errorf("%s: got %s want %s", vector.name, vector.got, vector.want)
		}
	}
}
