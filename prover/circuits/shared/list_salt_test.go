package shared_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func asciiTag(tag string) *big.Int {
	return new(big.Int).SetBytes([]byte(tag))
}

// The secret is ring_nullifier.wallet[0] of zolana/test-vectors/key_derivation.json.
func TestListSaltAndTagVector(t *testing.T) {
	secret, ok := new(big.Int).SetString("c82c60fd641271536147f6cc1cbb7bbf32635efe5f1220326e089501912080", 16)
	if !ok {
		t.Fatal("the secret is hex")
	}
	salt := ringtest.MustPoseidonHash(t, asciiTag("CRPS"), secret)
	tag := ringtest.MustPoseidonHash(t, asciiTag("CRPT"), salt)
	ringtest.PinVector(t, "registry/list_salt.json", map[string]string{
		"description":      "list_salt = Poseidon(CRPS, nullifier_secret) and list_tag = Poseidon(CRPT, list_salt), under the ring key of the wallet with signing secret [7; 32] on ring program [0xa1; 32]. Produced by prover/circuits/shared/list_salt_test.go with WRITE_AUDIT_VECTORS=1.",
		"signing_secret":   "0707070707070707070707070707070707070707070707070707070707070707",
		"ring_program_id":  "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1",
		"nullifier_secret": ringtest.FieldHex(secret),
		"list_salt":        ringtest.FieldHex(salt),
		"list_tag":         ringtest.FieldHex(tag),
	})
}
