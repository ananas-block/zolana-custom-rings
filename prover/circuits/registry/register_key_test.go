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
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var (
	keyRing   = big.NewInt(0x5a0f)
	keyMember = big.NewInt(0x0a)
)

// keyEnvelope seals a nullifier secret for keyMember under the default audit keys and binds the statement.
func keyEnvelope(t *testing.T) *registry.RegisterKeyCircuit {
	t.Helper()
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	keys := ringaudit.DefaultKeys(t)
	c := &registry.RegisterKeyCircuit{RingID: keyRing, Member: keyMember}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	ringtest.SetBytes(c.NullifierSecret[:], secret[:])
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	c.PublicInputHash = keyStatement(t, keyFields{ringID: keyRing, member: keyMember, nullifierPk: spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:])), listTag: listTagOf(t, secret[1:])}, keys.SealStream(t, secret[:], shared.NfKeyEncInfo))
	return c
}

type keyFields struct {
	ringID, member, nullifierPk, listTag *big.Int
}

func listTagOf(t *testing.T, secret []byte) *big.Int {
	t.Helper()
	return ringregistry.ListTag(t, ringregistry.ListSalt(t, new(big.Int).SetBytes(secret), keyRing))
}

// keyStatement is the CRRG statement of an honest witness, the honest solve holds it to the circuit's order.
func keyStatement(t *testing.T, f keyFields, sealed ringaudit.Sealed) *big.Int {
	t.Helper()
	return spptest.MustHashChain4(t, []*big.Int{
		big.NewInt(shared.RegisterKeyDomain), f.ringID, f.member, f.nullifierPk, f.listTag,
		sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, sealed.CiphertextHash,
	})
}

func solveRegisterKey(c *registry.RegisterKeyCircuit) error {
	return test.IsSolved(&registry.RegisterKeyCircuit{}, c, ecc.BN254.ScalarField())
}

func TestRegisterKeySealsTheEnrolledSecret(t *testing.T) {
	if err := solveRegisterKey(keyEnvelope(t)); err != nil {
		t.Fatal(err)
	}
}

// Each case changes one value of an honest envelope, the named frames raise the refusal.
func TestRegisterKeyRefusals(t *testing.T) {
	statement := []string{"[assertIsEqual]", "registry.(*RegisterKeyCircuit).Define"}
	secret := ringtest.Scalar(0x07)
	secret[0] = 0
	nullifierPk := func(t *testing.T) *big.Int { return spptest.MustNullifierPk(t, new(big.Int).SetBytes(secret[1:])) }
	sealedHonest := func(t *testing.T) ringaudit.Sealed {
		return ringaudit.DefaultKeys(t).SealStream(t, secret[:], shared.NfKeyEncInfo)
	}
	tests := []struct {
		name   string
		tamper func(*testing.T, *registry.RegisterKeyCircuit)
		frames []string
	}{
		{"secret with a nonzero lead byte", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			// The statement seals the 32 tampered bytes, the key still derives from the low 31.
			tampered := secret
			tampered[0] = 1
			c.NullifierSecret[0] = 1
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, keyMember, nullifierPk(t), listTagOf(t, tampered[1:])}, ringaudit.DefaultKeys(t).SealStream(t, tampered[:], shared.NfKeyEncInfo))
		}, statement},
		{"a zero secret", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			var zero [32]byte
			ringtest.SetBytes(c.NullifierSecret[:], zero[:])
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, keyMember, spptest.MustNullifierPk(t, big.NewInt(0)), listTagOf(t, zero[1:])}, ringaudit.DefaultKeys(t).SealStream(t, zero[:], shared.NfKeyEncInfo))
		}, []string{"[assertIsDifferent]", "registry.(*RegisterKeyCircuit).Define"}},
		{"statement naming a key the envelope does not seal", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, keyMember, big.NewInt(0x08), listTagOf(t, secret[1:])}, sealedHonest(t))
		}, statement},
		{"a list tag from another secret", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			other := ringtest.Scalar(0x09)
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, keyMember, nullifierPk(t), listTagOf(t, other[1:])}, sealedHonest(t))
		}, statement},
		{"a list tag from another ring", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			other := ringregistry.ListTag(t, ringregistry.ListSalt(t, new(big.Int).SetBytes(secret[1:]), big.NewInt(0x5a10)))
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, keyMember, nullifierPk(t), other}, sealedHonest(t))
		}, statement},
		{"another member's statement", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			c.PublicInputHash = keyStatement(t, keyFields{keyRing, big.NewInt(0x0b), nullifierPk(t), listTagOf(t, secret[1:])}, sealedHonest(t))
		}, statement},
		{"another ring's statement", func(t *testing.T, c *registry.RegisterKeyCircuit) {
			c.PublicInputHash = keyStatement(t, keyFields{big.NewInt(0x5a10), keyMember, nullifierPk(t), listTagOf(t, secret[1:])}, sealedHonest(t))
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
			c := keyEnvelope(t)
			tt.tamper(t, c)
			ringtest.RequireRefused(t, solveRegisterKey(c), tt.frames...)
		})
	}
}

func TestRegisterKeyKey(t *testing.T) {
	ringkey.RequirePinned(t, "custom_ring_register_key", ringkey.Compile(t, &registry.RegisterKeyCircuit{}))
}
