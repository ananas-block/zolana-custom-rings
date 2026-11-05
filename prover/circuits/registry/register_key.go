// Proves that the auditor can recover the secret behind the nullifier key an owner
// enrolls and the salt behind its list tag. SPP spends a note under Poseidon(secret)
// and the enrollment envelope gives that secret to the auditor. A ring owes its
// auditor the owner's spends, each nullifier derives from that secret, and owes
// its private lists one fixed record
// key per owner, that key derives from the salt. The ring's `Enroll` verifies the proof
// and creates the immutable SPP credential from the same verified fields atomically.
// Without it an owner could enroll a key whose nullifiers no auditor can compute,
// or a salt a private block never reaches.
//
// Read after shared/derivation.go, shared/envelope.go. Read before registry/credential.go,
// registry/credential_write.go, policy/subjects.go, prover/ring/ring.go.

package registry

import (
	"slices"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The nullifier key is Poseidon of the nonzero 31 byte secret, the same hash nullifierPkGadget in zolana/prover/server/circuits/spp_transaction/shared/inputs.go takes a spent note's key from.
// 2. The list tag is Poseidon(CRPT, salt) of the nonzero 31 byte salt.
// 3. The ciphertext seals exactly those two values, 32 bytes each with a zero lead, to AuditorPk under CRING/nfk, so the auditor recovers both behind the enrolled key and tag.
// 4. The statement binds the ring, the member, the key, the list tag, both tagged envelope keys and the ciphertext hash.
//
// The circuit holds neither value to a wallet derivation, a wallet that seals another secret harms itself alone. It does not prove EphSk fresh, see shared/envelope.go.

type RegisterKeyCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	RingID          frontend.Variable
	Member          frontend.Variable
	NullifierSecret [32]frontend.Variable
	ListSalt        [32]frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
}

func (c *RegisterKeyCircuit) Define(api frontend.API) error {
	// 1. A zero lead byte keeps the secret below q, the envelope's cipher bounds the other 31 bytes.
	// Below 2^248 the packed bytes are the integer itself, the sealed bytes, the key and SPP's nullifier secret name one value with no alias secret + q.
	api.AssertIsEqual(c.NullifierSecret[0], 0)
	secret := shared.PackBounded(api, c.NullifierSecret[1:])[0]
	// Poseidon(0) is the zero key, never enrolled.
	// Secret zero remains public, and an auditor can derive the nullifier from the proven note opening without enrollment.
	// A zero-key output still reads its owner credential when a salted payee check is active.
	api.AssertIsDifferent(secret, 0)
	nullifierPk := gadget.PoseidonHash(api, []frontend.Variable{secret})
	// 2. A salt the envelope does not hold would leave the owner off the auditor's list writes.
	// The tag commits to the owner's one salt. policy/subjects.go forces a present row's salt to open the tag, and so forces the key ListKey(owner, salt) a private entry sits under, with no choice left to the prover.
	// A changed salt would select another private record. Enroll reserves one address for the ring and member and creates no replacement path.
	// The immutable state hash binds the sealed key, salt tag and exact envelope. Viewing-key rotation stays outside the credential.
	// Every private owner write proves both credential state inclusion and address inclusion before the program raises the absence floor.
	// A salted read at or above that floor cannot prove the written owner absent, even while unrelated enrollments remain queued.
	api.AssertIsEqual(c.ListSalt[0], 0)
	salt := shared.PackBounded(api, c.ListSalt[1:])[0]
	// A zero salt would let anyone who knows the owner compute ListKey(owner, 0). The circuit refuses only zero, the wallet's derivation supplies the entropy.
	api.AssertIsDifferent(salt, 0)
	listTag := shared.ListTag(api, salt)
	// The cipher under CRING/nfk bounds every ciphertext byte.
	// The key and the tag hash the same wires the cipher seals, the auditor reads the values behind them. The cipher's byte tables also bound the plaintext bytes both packings above rely on.
	sealed := shared.Envelope{Plaintext: slices.Concat(c.NullifierSecret[:], c.ListSalt[:]), EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.NfKeyEncInfo}.SealStream(api)
	// 3. The statement binds the ring, member and auditor key the program supplies, and the instruction's envelope.
	// RingID and Member enter only the statement. Enroll derives the ring id from its program id and the member from the owner signer.
	// The authenticated RingPolicy supplies the auditor key, and the verified fields also construct the SPP output.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, nullifierPk, listTag, sealed)))
	return nil
}

// The CRRG element order matches AuditCredential.elements in program-libs/interface/src/accounts/credential.rs.
func (c *RegisterKeyCircuit) statement(api frontend.API, nullifierPk, listTag frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	return (Credential{
		RingID: c.RingID, Member: c.Member, NullifierPk: nullifierPk, ListTag: listTag,
		Aud: [2]frontend.Variable(sealed.Auditor), Eph: [2]frontend.Variable(sealed.Eph),
		CtHash: gadget.HashBoundedBytes(api, sealed.Ciphertext),
	}).Elements(shared.RegisterKeyDomain)
}
