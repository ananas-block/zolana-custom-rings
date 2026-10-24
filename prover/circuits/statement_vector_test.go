package circuits

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type depositStatementCircuit struct {
	PublicInputHash    frontend.Variable `gnark:",public"`
	ContextHash        frontend.Variable
	Count              frontend.Variable
	Anonymous          frontend.Variable
	KeyEscrow          frontend.Variable
	MemberRegistryRoot frontend.Variable
	Commitments        [MaxDeposits]frontend.Variable
	Ciphertext         [MaxDeposits * DepositOpeningBytes]frontend.Variable
	AuditorPubkey      [33]frontend.Variable
	EphPk              [33]frontend.Variable
}

func (c *depositStatementCircuit) Define(api frontend.API) error {
	circuit := &DepositCircuit{
		ContextHash: c.ContextHash, Count: c.Count, Anonymous: c.Anonymous, KeyEscrow: c.KeyEscrow, MemberRegistryRoot: c.MemberRegistryRoot,
	}
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, c.EphPk[:]),
		Ciphertext: c.Ciphertext[:],
	}
	statement := circuit.statement(api, ringgadget.SelectCount(api, c.Count, 1, MaxDeposits), c.Commitments[:], sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, statement))
	return nil
}

// The Rust ciphertexts are no sealed envelopes.
func TestDepositStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		Deposit struct {
			ContextHash        string   `json:"context_hash"`
			Anonymous          bool     `json:"anonymous"`
			OwnerUtxoHashes    []string `json:"owner_utxo_hashes"`
			Ciphertexts        []string `json:"ciphertexts"`
			AuditorPubkey      string   `json:"auditor_pubkey"`
			EphPk              string   `json:"eph_pk"`
			MemberRegistryRoot *string  `json:"member_registry_root"`
			PublicInputHash    string   `json:"public_input_hash"`
		} `json:"deposit"`
	}
	ringtest.ReadVector(t, "ring-statements.json", &vectors)
	v := vectors.Deposit
	if len(v.OwnerUtxoHashes) != len(v.Ciphertexts) || len(v.OwnerUtxoHashes) == 0 || len(v.OwnerUtxoHashes) > MaxDeposits {
		t.Fatalf("%d commitments for %d ciphertexts", len(v.OwnerUtxoHashes), len(v.Ciphertexts))
	}
	witness := &depositStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash), ContextHash: ringtest.VectorField(t, v.ContextHash),
		Count: len(v.OwnerUtxoHashes), Anonymous: ringtest.Bit(v.Anonymous), KeyEscrow: 0, MemberRegistryRoot: 0,
	}
	if v.MemberRegistryRoot != nil {
		witness.KeyEscrow, witness.MemberRegistryRoot = 1, ringtest.VectorField(t, *v.MemberRegistryRoot)
	}
	for i := range witness.Commitments {
		witness.Commitments[i] = 0
	}
	for i := range witness.Ciphertext {
		witness.Ciphertext[i] = 0
	}
	for i, commitment := range v.OwnerUtxoHashes {
		witness.Commitments[i] = ringtest.VectorField(t, commitment)
		copy(witness.Ciphertext[i*DepositOpeningBytes:(i+1)*DepositOpeningBytes], ringtest.VectorWires(t, v.Ciphertexts[i], DepositOpeningBytes))
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphPk[:], ringtest.VectorWires(t, v.EphPk, 33))
	ringtest.RequirePublicInputBound(t, &depositStatementCircuit{}, witness)
}
