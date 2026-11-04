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
	ListScope       frontend.Variable
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
	statement := (&RegisterKeyCircuit{RingID: c.RingID, ListScope: c.ListScope, Member: c.Member}).statement(api, c.NullifierPk, c.ListTag, sealed)
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
			ListScope       string `json:"list_scope"`
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
		ListScope:       ringtest.VectorField(t, v.ListScope),
	}
	copy(witness.AuditorPubkey[:], ringtest.VectorWires(t, v.AuditorPubkey, 33))
	copy(witness.EphU[:], ringtest.VectorWires(t, v.EphU, 32))
	copy(witness.Ciphertext[:], ringtest.VectorWires(t, v.Ciphertext, 32))
	ringtest.RequirePublicInputBound(t, &keyStatementCircuit{}, witness)
}

type applyStatementFields struct {
	PublicInputHash                                                    frontend.Variable `gnark:",public"`
	OldRoot, NewRoot, OldNextIndex, NewNextIndex, ChainStart, ChainEnd frontend.Variable
	Count                                                              frontend.Variable
}

type recordsStatementCircuit struct {
	applyStatementFields
}

func (c *recordsStatementCircuit) Define(api frontend.API) error {
	statement := (&ApplyRecordsCircuit{OldRoot: c.OldRoot, NewRoot: c.NewRoot, OldNextIndex: c.OldNextIndex, NewNextIndex: c.NewNextIndex, ChainStart: c.ChainStart, ChainEnd: c.ChainEnd, Count: c.Count}).statement()
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

type enrollmentsStatementCircuit struct {
	applyStatementFields
}

func (c *enrollmentsStatementCircuit) Define(api frontend.API) error {
	statement := (&ApplyEnrollmentsCircuit{OldRoot: c.OldRoot, NewRoot: c.NewRoot, OldNextIndex: c.OldNextIndex, NewNextIndex: c.NewNextIndex, ChainStart: c.ChainStart, ChainEnd: c.ChainEnd, Count: c.Count}).statement()
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, statement))
	return nil
}

type applyStatementVector struct {
	OldRoot         string `json:"old_root"`
	NewRoot         string `json:"new_root"`
	OldNextIndex    uint32 `json:"old_next_index"`
	NewNextIndex    uint32 `json:"new_next_index"`
	ChainStart      string `json:"chain_start"`
	ChainEnd        string `json:"chain_end"`
	Count           uint64 `json:"count"`
	PublicInputHash string `json:"public_input_hash"`
}

func (v applyStatementVector) fields(t *testing.T) applyStatementFields {
	t.Helper()
	return applyStatementFields{
		PublicInputHash: ringtest.VectorField(t, v.PublicInputHash),
		OldRoot:         ringtest.VectorField(t, v.OldRoot), NewRoot: ringtest.VectorField(t, v.NewRoot),
		OldNextIndex: v.OldNextIndex, NewNextIndex: v.NewNextIndex,
		ChainStart: ringtest.VectorField(t, v.ChainStart), ChainEnd: ringtest.VectorField(t, v.ChainEnd), Count: v.Count,
	}
}

func TestApplyStatementsMatchRustVector(t *testing.T) {
	var vectors struct {
		ApplyRecords     applyStatementVector `json:"apply_records"`
		ApplyEnrollments applyStatementVector `json:"apply_enrollments"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	ringtest.RequirePublicInputBound(t, &recordsStatementCircuit{}, &recordsStatementCircuit{applyStatementFields: vectors.ApplyRecords.fields(t)})
	ringtest.RequirePublicInputBound(t, &enrollmentsStatementCircuit{}, &enrollmentsStatementCircuit{applyStatementFields: vectors.ApplyEnrollments.fields(t)})
}
