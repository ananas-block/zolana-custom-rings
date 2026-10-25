package registry

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type keyStatementCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Member          frontend.Variable
	NullifierPk     frontend.Variable
	AuditorPubkey   [33]frontend.Variable
	EphU            [32]frontend.Variable
	Ciphertext      [32]frontend.Variable
}

func (c *keyStatementCircuit) Define(api frontend.API) error {
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, append([]frontend.Variable{4}, c.EphU[:]...)),
		Ciphertext: c.Ciphertext[:],
	}
	statement := (&RegisterKeyCircuit{Member: c.Member}).statement(api, c.NullifierPk, sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// The Rust ciphertext is no sealed envelope.
func TestRegisterKeyStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		RegisterKey struct {
			Member          string `json:"member"`
			NullifierPk     string `json:"nullifier_pk"`
			AuditorPubkey   string `json:"auditor_pubkey"`
			EphU            string `json:"eph_u"`
			Ciphertext      string `json:"ciphertext"`
			PublicInputHash string `json:"public_input_hash"`
		} `json:"register_key"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.RegisterKey
	witness := &keyStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		Member:          ringtest.VectorField(t, v.Member),
		NullifierPk:     ringtest.VectorField(t, v.NullifierPk),
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphU[:], ringtest.VectorWires(t, v.EphU, 32))
	copy(witness.Ciphertext[:], ringtest.VectorWires(t, v.Ciphertext, 32))
	ringtest.RequirePublicInputBound(t, &keyStatementCircuit{}, witness)
}
