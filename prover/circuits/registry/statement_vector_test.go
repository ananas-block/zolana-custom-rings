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
	RingID          frontend.Variable
	Member          frontend.Variable
	NullifierPk     frontend.Variable
	ListTag         frontend.Variable
	AuditorPubkey   [33]frontend.Variable
	EphU            [32]frontend.Variable
	Ciphertext      [64]frontend.Variable
}

func (c *keyStatementCircuit) Define(api frontend.API) error {
	sealed := shared.Sealed{
		Auditor:    gadget.PackBytesBE(api, c.AuditorPubkey[:]),
		Eph:        gadget.PackBytesBE(api, append([]frontend.Variable{4}, c.EphU[:]...)),
		Ciphertext: c.Ciphertext[:],
	}
	statement := (&RegisterKeyCircuit{RingID: c.RingID, Member: c.Member}).statement(api, c.NullifierPk, c.ListTag, sealed)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

// The Rust ciphertext is no sealed envelope.
func TestRegisterKeyStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		RegisterKey struct {
			RingID          string `json:"ring_id"`
			Member          string `json:"member"`
			NullifierPk     string `json:"nullifier_pk"`
			ListTag         string `json:"list_tag"`
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
		RingID:          ringtest.VectorField(t, v.RingID),
		Member:          ringtest.VectorField(t, v.Member),
		NullifierPk:     ringtest.VectorField(t, v.NullifierPk),
		ListTag:         ringtest.VectorField(t, v.ListTag),
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphU[:], ringtest.VectorWires(t, v.EphU, 32))
	copy(witness.Ciphertext[:], ringtest.VectorWires(t, v.Ciphertext, 64))
	ringtest.RequirePublicInputBound(t, &keyStatementCircuit{}, witness)
}

type recordsStatementCircuit struct {
	PublicInputHash                                                    frontend.Variable `gnark:",public"`
	OldRoot, NewRoot, OldNextIndex, NewNextIndex, ChainStart, ChainEnd frontend.Variable
	Count, Restrictive                                                 frontend.Variable
	CredentialWrites, PrivateRingID, CredentialOwner, AddressRoot      frontend.Variable
	StateRoots                                                         [][2]frontend.Variable
}

func (c *recordsStatementCircuit) Define(api frontend.API) error {
	statement := (&PrivateApplyRecordsCircuit{
		ApplyRecordsCircuit: ApplyRecordsCircuit{
			OldRoot: c.OldRoot, NewRoot: c.NewRoot, OldNextIndex: c.OldNextIndex, NewNextIndex: c.NewNextIndex,
			ChainStart: c.ChainStart, ChainEnd: c.ChainEnd, Count: c.Count,
		},
		CredentialWrites: c.CredentialWrites, PrivateRingID: c.PrivateRingID,
		CredentialOwner: c.CredentialOwner, AddressRoot: c.AddressRoot, StateRoots: c.StateRoots,
	}).statement(c.Restrictive)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

type applyStatementVector struct {
	OldRoot          string   `json:"old_root"`
	NewRoot          string   `json:"new_root"`
	OldNextIndex     uint32   `json:"old_next_index"`
	NewNextIndex     uint32   `json:"new_next_index"`
	ChainStart       string   `json:"chain_start"`
	ChainEnd         string   `json:"chain_end"`
	Count            uint64   `json:"count"`
	Restrictive      bool     `json:"restrictive"`
	CredentialWrites uint16   `json:"credential_writes"`
	PrivateRingID    string   `json:"private_ring_id"`
	CredentialFields []string `json:"credential_fields"`
	PublicInputHash  string   `json:"public_input_hash"`
}

func TestApplyRecordsStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		ApplyRecords applyStatementVector `json:"apply_records"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.ApplyRecords
	if len(v.CredentialFields) < 4 || len(v.CredentialFields)%2 != 0 {
		t.Fatalf("invalid credential statement length %d", len(v.CredentialFields))
	}
	witness := &recordsStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		OldRoot:         ringtest.VectorField(t, v.OldRoot), NewRoot: ringtest.VectorField(t, v.NewRoot),
		OldNextIndex: v.OldNextIndex, NewNextIndex: v.NewNextIndex,
		ChainStart: ringtest.VectorField(t, v.ChainStart), ChainEnd: ringtest.VectorField(t, v.ChainEnd), Count: v.Count, Restrictive: ringtest.Bit(v.Restrictive),
		CredentialWrites: uint64(v.CredentialWrites), PrivateRingID: ringtest.VectorField(t, v.PrivateRingID),
		CredentialOwner: ringtest.VectorField(t, v.CredentialFields[0]), AddressRoot: ringtest.VectorField(t, v.CredentialFields[1]),
		StateRoots: make([][2]frontend.Variable, (len(v.CredentialFields)-2)/2),
	}
	for i := range witness.StateRoots {
		witness.StateRoots[i] = [2]frontend.Variable{ringtest.VectorField(t, v.CredentialFields[2+2*i]), ringtest.VectorField(t, v.CredentialFields[3+2*i])}
	}
	shape := &recordsStatementCircuit{StateRoots: make([][2]frontend.Variable, len(witness.StateRoots))}
	ringtest.RequirePublicInputBound(t, shape, witness)
}

type publicRecordsStatementCircuit struct {
	PublicInputHash                                                    frontend.Variable `gnark:",public"`
	OldRoot, NewRoot, OldNextIndex, NewNextIndex, ChainStart, ChainEnd frontend.Variable
	Count, Restrictive                                                 frontend.Variable
}

func (c *publicRecordsStatementCircuit) Define(api frontend.API) error {
	statement := (&ApplyRecordsCircuit{
		OldRoot: c.OldRoot, NewRoot: c.NewRoot, OldNextIndex: c.OldNextIndex, NewNextIndex: c.NewNextIndex,
		ChainStart: c.ChainStart, ChainEnd: c.ChainEnd, Count: c.Count,
	}).statement(c.Restrictive)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

func TestPublicApplyRecordsStatementMatchesRustVector(t *testing.T) {
	var vectors struct {
		ApplyRecords applyStatementVector `json:"apply_records_public"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	v := vectors.ApplyRecords
	witness := &publicRecordsStatementCircuit{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		OldRoot:         ringtest.VectorField(t, v.OldRoot), NewRoot: ringtest.VectorField(t, v.NewRoot),
		OldNextIndex: v.OldNextIndex, NewNextIndex: v.NewNextIndex,
		ChainStart: ringtest.VectorField(t, v.ChainStart), ChainEnd: ringtest.VectorField(t, v.ChainEnd), Count: v.Count, Restrictive: ringtest.Bit(v.Restrictive),
	}
	ringtest.RequirePublicInputBound(t, &publicRecordsStatementCircuit{}, witness)
}
