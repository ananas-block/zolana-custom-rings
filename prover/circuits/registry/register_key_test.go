package registry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// keyEnvelope seals a nullifier secret for member under the default audit keys and binds the statement.
func keyEnvelope(t *testing.T, member *big.Int) *registry.RegisterKeyCircuit {
	t.Helper()
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	keys := ringaudit.DefaultKeys(t)
	c := &registry.RegisterKeyCircuit{Member: member}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	ringtest.SetBytes(c.NullifierSecret[:], secret[:])
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	c.PublicInputHash = keyStatement(t, member, spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:])), keys.Seal(t, secret[:], shared.NfKeyEncInfo))
	return c
}

// keyStatement is the CRRG statement of an honest witness, the honest solve holds it to the circuit's order.
func keyStatement(t *testing.T, member, nullifierPk *big.Int, sealed ringaudit.Sealed) *big.Int {
	t.Helper()
	return spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(shared.RegisterKeyDomain), member, nullifierPk,
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
	})
}

func solveRegisterKey(c *registry.RegisterKeyCircuit) error {
	return test.IsSolved(&registry.RegisterKeyCircuit{}, c, ecc.BN254.ScalarField())
}

func TestRegisterKeySealsTheEscrowedSecret(t *testing.T) {
	if err := solveRegisterKey(keyEnvelope(t, big.NewInt(0x0a))); err != nil {
		t.Fatal(err)
	}
}

// Each case changes one value of an honest envelope, the named frames raise the refusal.
func TestRegisterKeyRefusals(t *testing.T) {
	statement := []string{"[assertIsEqual]", "registry.(*RegisterKeyCircuit).Define"}
	tests := []struct {
		name   string
		tamper func(*testing.T, *registry.RegisterKeyCircuit)
		frames []string
	}{
		{"secret with a nonzero lead byte", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			// The statement seals the 32 tampered bytes, the key still derives from the low 31.
			secret := ringtest.Scalar(0x07)
			secret[0] = 1
			sealed := ringaudit.DefaultKeys(t).Seal(t, secret[:], shared.NfKeyEncInfo)
			c.NullifierSecret[0] = 1
			c.PublicInputHash = keyStatement(t, big.NewInt(0x0a), spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:])), sealed)
		}, statement},
		{"statement naming a key the envelope does not seal", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			secret := ringtest.Scalar(0x07)
			secret[0] = 0
			sealed := ringaudit.DefaultKeys(t).Seal(t, secret[:], shared.NfKeyEncInfo)
			c.PublicInputHash = keyStatement(t, big.NewInt(0x0a), spptest.MustNullifierPk(t, big.NewInt(0x08)), sealed)
		}, statement},
		{"envelope sealed to another auditor", func(_ *testing.T, c *registry.RegisterKeyCircuit) {
			c.AuditorPk[1] = 0
		}, statement},
		{"secret bytes outside 0..255 packing to the same key", func(_ *testing.T, c *registry.RegisterKeyCircuit) {
			// Moving 256 between adjacent bytes keeps the key, the envelope's byte table refuses the encoding.
			c.NullifierSecret[1], c.NullifierSecret[2] = c.NullifierSecret[1].(int)-1, c.NullifierSecret[2].(int)+256
		}, []string{"shared.Envelope.Seal", "registry.(*RegisterKeyCircuit).Define"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := keyEnvelope(t, big.NewInt(0x0a))
			tt.tamper(t, c)
			ringtest.RequireRefused(t, solveRegisterKey(c), tt.frames...)
		})
	}
}

func TestRegisterKeyKey(t *testing.T) {
	ringkey.RequirePinned(t, "custom_ring_register_key", ringkey.Compile(t, &registry.RegisterKeyCircuit{}))
}
