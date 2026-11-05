package circuits

import (
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type depositStatementCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	RingID          frontend.Variable
	CredentialOwner frontend.Variable
	AddressRoot     frontend.Variable
	StateRoots      [][2]frontend.Variable
	OwnRoot         frontend.Variable
	CuratorRoot     frontend.Variable
	PolicyHash      frontend.Variable
	Assets          [MaxDeposits]frontend.Variable
	Amounts         [MaxDeposits]frontend.Variable
	Commitments     [MaxDeposits]frontend.Variable
	Ciphertext      [MaxDeposits * DepositRecordLen]frontend.Variable
	AuditorPubkey   [33]frontend.Variable
	EphPk           [33]frontend.Variable
}

func (c *depositStatementCircuit) Define(api frontend.API) error {
	circuit := &DepositCircuit{
		ContextHash: c.ContextHash, Count: c.Count, OwnRoot: c.OwnRoot,
		Credentials: policy.Credentials{CredentialOwner: c.CredentialOwner, AddressRoot: c.AddressRoot, StateRoots: c.StateRoots[:]},
		PolicyHash:  c.PolicyHash, Assets: c.Assets[:], Amounts: c.Amounts[:],
	}
	circuit.CuratorRoot = c.CuratorRoot
	circuit.RingProgramID = c.RingID
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, c.EphPk[:]),
		Ciphertext: c.Ciphertext[:],
	}
	statement := circuit.statement(api, ringgadget.SelectCount(api, c.Count, 1, MaxDeposits), c.Commitments[:], sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// The Rust ciphertexts are no sealed envelopes.
func TestDepositStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		Deposit struct {
			ContextHash      string   `json:"context_hash"`
			OwnerUtxoHashes  []string `json:"owner_utxo_hashes"`
			Ciphertexts      []string `json:"ciphertexts"`
			AuditorPubkey    string   `json:"auditor_pubkey"`
			EphPk            string   `json:"eph_pk"`
			Assets           []string `json:"assets"`
			Amounts          []uint64 `json:"amounts"`
			RingID           string   `json:"ring_id"`
			CredentialFields []string `json:"credential_fields"`
			OwnRoot          *string  `json:"member_registry_root"`
			CuratorRoot      *string  `json:"curator_root"`
			PolicyHash       *string  `json:"policy_hash"`
			PublicInputHash  string   `json:"public_input_hash"`
		} `json:"deposit"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.Deposit
	if len(v.OwnerUtxoHashes) != len(v.Ciphertexts) || len(v.OwnerUtxoHashes) != len(v.Assets) || len(v.Assets) != len(v.Amounts) || len(v.OwnerUtxoHashes) == 0 || len(v.OwnerUtxoHashes) > MaxDeposits {
		t.Fatalf("%d commitments for %d ciphertexts", len(v.OwnerUtxoHashes), len(v.Ciphertexts))
	}
	witness := &depositStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash), ContextHash: ringtest.VectorField(t, v.ContextHash),
		Count: len(v.OwnerUtxoHashes), RingID: ringtest.VectorField(t, v.RingID), OwnRoot: 0, CuratorRoot: 0, PolicyHash: 0,
	}
	if len(v.CredentialFields) < 4 || len(v.CredentialFields)%2 != 0 {
		t.Fatalf("invalid credential statement length %d", len(v.CredentialFields))
	}
	witness.StateRoots = make([][2]frontend.Variable, (len(v.CredentialFields)-2)/2)
	witness.CredentialOwner = ringtest.VectorField(t, v.CredentialFields[0])
	witness.AddressRoot = ringtest.VectorField(t, v.CredentialFields[1])
	for i := range witness.StateRoots {
		witness.StateRoots[i] = [2]frontend.Variable{ringtest.VectorField(t, v.CredentialFields[2+2*i]), ringtest.VectorField(t, v.CredentialFields[3+2*i])}
	}
	if v.OwnRoot != nil {
		witness.OwnRoot = ringtest.VectorField(t, *v.OwnRoot)
	}
	if v.CuratorRoot != nil {
		witness.CuratorRoot = ringtest.VectorField(t, *v.CuratorRoot)
	}
	if v.PolicyHash != nil {
		witness.PolicyHash = ringtest.VectorField(t, *v.PolicyHash)
	}
	for i := range witness.Commitments {
		witness.Commitments[i], witness.Assets[i], witness.Amounts[i] = 0, 0, 0
	}
	for i, asset := range v.Assets {
		witness.Assets[i], witness.Amounts[i] = ringtest.VectorField(t, asset), v.Amounts[i]
	}
	for i := range witness.Ciphertext {
		witness.Ciphertext[i] = 0
	}
	for i, commitment := range v.OwnerUtxoHashes {
		witness.Commitments[i] = ringtest.VectorField(t, commitment)
		copy(witness.Ciphertext[i*DepositRecordLen:(i+1)*DepositRecordLen], ringtest.VectorWires(t, v.Ciphertexts[i], DepositRecordLen))
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphPk[:], ringtest.VectorWires(t, v.EphPk, 33))
	shape := &depositStatementCircuit{StateRoots: make([][2]frontend.Variable, len(witness.StateRoots))}
	ringtest.RequirePublicInputBound(t, shape, witness)
}
