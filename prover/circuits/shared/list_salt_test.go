package shared_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func asciiTag(tag string) *big.Int {
	return new(big.Int).SetBytes([]byte(tag))
}

// The secret is eddsa_rail.nullifier_secret of zolana/test-vectors/key_derivation.json.
func TestListSaltAndTagVector(t *testing.T) {
	secret, ok := new(big.Int).SetString("f172e55a6d39bf1602b0ef9d7276882b68c84dea44867b491091056e36cea1", 16)
	if !ok {
		t.Fatal("the secret is hex")
	}
	ringID := big.NewInt(0x5c0e)
	salt := ringtest.MustPoseidonHash(t, asciiTag("CRPS"), secret, ringID)
	tag := ringtest.MustPoseidonHash(t, asciiTag("CRPT"), salt)
	ringtest.PinVector(t, "registry/list_salt.json", map[string]string{
		"description":      "list_salt = Poseidon(CRPS, nullifier_secret, ring_id) and list_tag = Poseidon(CRPT, list_salt), under the nullifier secret of the wallet with signing secret [7; 32]. Produced by prover/circuits/shared/list_salt_test.go with WRITE_AUDIT_VECTORS=1.",
		"signing_secret":   "0707070707070707070707070707070707070707070707070707070707070707",
		"nullifier_secret": ringtest.FieldHex(secret),
		"ring_id":          ringtest.FieldHex(ringID),
		"list_salt":        ringtest.FieldHex(salt),
		"list_tag":         ringtest.FieldHex(tag),
	})
}
