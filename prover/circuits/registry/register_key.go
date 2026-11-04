// Proves that the auditor can recover the secret behind the nullifier key a
// member enrolls, and that the member's list tag derives from the same secret.
// Storage `Enroll` verifies the proof in the same instruction.
//
// Read after shared/envelope.go. Read before prover/ring/ring.go.

package registry

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The nullifier key is Poseidon of the nonzero 31-byte nullifier secret the envelope seals to AuditorPk, so the auditor recovers the secret behind the enrolled key.
// 2. The list tag is Poseidon(CRPT, Poseidon(CRPS, secret, ring)) over the same secret and the statement's ring.
// 3. The statement binds the ring, the member, the key, the list tag, both tagged envelope keys and the ciphertext hash, the program computes the member and reads the ring and the auditor key from the tracking registry.

type RegisterKeyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RingID          frontend.Variable
	Member          frontend.Variable
	NullifierSecret [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *RegisterKeyCircuit) Define(api frontend.API) error {
	// 1. A zero lead byte keeps the secret below q, the envelope's cipher bounds the other 31 bytes.
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	secret := shared.PackBounded(api, c.NullifierSecret[1:])[0]
	// Poseidon(0) is the zero key, never enrolled.
	api.AssertIsDifferent(secret, 0)
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secret})
	// 2. A list tag from another secret would move the owner's private list position.
	listTag := shared.ListTag(api, shared.ListSalt(api, secret, c.RingID))
	// The envelope seals the same 32 bytes to the auditor under CRING/nfk1, its cipher bounds every ciphertext byte.
	sealed := shared.Envelope{Plaintext: c.NullifierSecret[:], EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.NfKeyEncInfo}.SealStream(api)
	// 3. The statement names the envelope the program reads from the instruction.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, nullifierPk, listTag, sealed)))
	return nil
}

// statement mirrors RegisterKeyStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *RegisterKeyCircuit) statement(api frontend.API, nullifierPk, listTag frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	return append([]frontend.Variable{shared.RegisterKeyDomain, c.RingID, c.Member, nullifierPk, listTag}, sealed.StatementFields(api)...)
}
