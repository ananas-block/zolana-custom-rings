package ringaudit

import (
	"encoding/hex"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func TestAuditEnvelopeVector(t *testing.T) {
	k := DefaultKeys(t)
	ciphertext := k.auditStreamCiphertext(t, k.txViewingSk[:])
	if got := hex.EncodeToString(ciphertext); got != "da94f616e95702bdea89178dd9c4547393ebce9d47e67d0cac1533f13b678b90" {
		t.Fatalf("auditor ciphertext: %s", got)
	}
	if got := hex.EncodeToString(ringtest.HashBytes(t, ciphertext).FillBytes(make([]byte, 32))); got != "2ec8fca72d305d1cfc2ea01acb5058150dd251c32da26baa29affbca9f7779d9" {
		t.Fatalf("auditor ciphertext hash: %s", got)
	}
}
