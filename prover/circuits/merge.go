// Proves that the auditor opens the output of a ring's SPP merge, under the owner, asset
// and amount the output commits and the seed its blinding derives from. The SPP proof ties
// every input to that owner, asset and sum, the ring proof opens no input and one key
// serves every merge width.
//
// Read after shared/envelope.go, registry/opening.go.
// Read before prover/ring/ring.go.

package circuits

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. OutputUtxoHash commits the record's owner, nullifier key, mint and amount under the TMOB blinding of Seed and FirstNullifier.
// 2. Only the auditor opens the record, its plaintext is the kind, amount, owner key, mint, nullifier key and seed in one canonical encoding.
// 3. A nullifier key off ZeroNullifierPk has its row under TrackingRoot and its owner stays hidden, ZeroNullifierPk reads no row and publishes its owner.
// 4. No list, guard, cap or co-signer rule is proven, a merge keeps one owner's value in one asset.

// MergeRecordLen mirrors OPENING_RECORD_LEN in program-libs/interface/src/proof/audit_stream.rs.
const MergeRecordLen = audit.RecordLen + 32

// MergeCircuit binds a ring's SPP merge output to a record only its auditor opens.
type MergeCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OutputUtxoHash frontend.Variable
	FirstNullifier frontend.Variable
	RingProgramID  frontend.Variable
	AuditorPk      [32]frontend.Variable
	Payer          frontend.Variable
	TrackingRoot   frontend.Variable

	EphSk [32]frontend.Variable
	// The record's encoding binds OwnerPkHash to OwnerKey and Asset to MintChunks.
	OwnerKey    [32]frontend.Variable
	OwnerPkHash frontend.Variable
	MintChunks  [2]frontend.Variable
	Asset       frontend.Variable
	Amount      frontend.Variable
	NullifierPk frontend.Variable
	// The nullifier secret off ZeroNullifierPk, the private merge seed under it, SPP's proof holds it to the key.
	Seed               frontend.Variable
	OutputTreeID       frontend.Variable
	OutputRingDataHash frontend.Variable
	Tracking           registry.TrackingOpening
}

func (c *MergeCircuit) Define(api frontend.API) error {
	zeroKey := api.IsZero(api.Sub(c.NullifierPk, shared.ZeroNullifierPk))
	hidden := api.Sub(1, zeroKey)
	// 1. A hidden owner cannot pay, the payer is public.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(api.Sub(c.OwnerPkHash, c.Payer))})
	// 2. A hidden owner's key is its row's, a zero key reads no row and its owner signs in SPP.
	row := c.Tracking.Resolve(api, hidden, c.TrackingRoot, c.OwnerPkHash)
	api.AssertIsEqual(row.Present, hidden)
	api.AssertIsEqual(row.NullifierPk, api.Mul(hidden, c.NullifierPk))

	// 3. The output is the SPP merge output, the auditor rebuilds its hash from the record.
	api.AssertIsEqual(c.OutputUtxoHash, transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHash, c.NullifierPk}),
		Asset: c.Asset, Amount: c.Amount, Blinding: mergeshared.MergeOutputBlinding(api, c.Seed, c.FirstNullifier),
		DataHash: 0, RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID))

	// 4. One encoding per record, a transfer's record followed by the seed.
	rc := rangecheck.New(api)
	seedBytes := ringgadget.FieldToBytesBEWith(api, rc, c.Seed)
	plaintext := slices.Concat(audit.RecordOpening{
		Live: 1, Kind: audit.KindRing, Amount: c.Amount, OwnerPkHash: c.OwnerPkHash, NullifierPk: c.NullifierPk, Asset: c.Asset,
		OwnerKey: c.OwnerKey, MintChunks: c.MintChunks,
	}.Encode(api, rc), seedBytes[:])
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.MergeEncInfo}.SealStream(api)

	// 5. The statement names the SPP merge, the ring, the record and the owner SPP makes sign, mirrored by MergePublicInput::elements in program-libs/interface/src/instructions/merge.rs.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, slices.Concat(
		[]frontend.Variable{shared.MergeStatementDomain, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID},
		sealed.StatementFields(api),
		[]frontend.Variable{c.Payer, api.Mul(zeroKey, c.OwnerPkHash), c.TrackingRoot},
	)))
	return nil
}
