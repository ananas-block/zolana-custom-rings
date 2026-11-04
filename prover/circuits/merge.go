// Proves that the auditor opens the output of a ring's SPP merge, under the owner, asset
// and amount the output commits and the seed its blinding derives from. The SPP proof ties
// every input to that owner, asset and sum, so this proof opens no input and has one key
// for every merge width.
//
// Read after shared/envelope.go, registry/opening.go.
// Read before prover/ring/ring.go.

package circuits

import (
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

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

const (
	// MergeRecordLen mirrors MERGE_RECORD_LEN in program-libs/interface/src/instructions/merge.rs.
	MergeRecordLen = 144
	// mergeRecordKindRing mirrors MergeRecordKind::Ring.
	mergeRecordKindRing = 1
	mergeRecordReserved = 7
	mergeAmountBytes    = 8
)

// trackingLeafDomain = "CRTK"
const trackingLeafDomain = 0x4352544b

// TrackingRow opens one owner's row of the ring's tracking tree.
type TrackingRow struct {
	Next, CtHash, View0, View1, Revision, ListTag frontend.Variable
	Path                                          registry.QuadPath
}

// Root folds the leaf that names member and its nullifier key, another member's or another key's row fails against the tracking root.
func (r TrackingRow) Root(api frontend.API, member, nullifierPk frontend.Variable) frontend.Variable {
	return r.Path.Root(api, gadget.PoseidonHash(api, []frontend.Variable{trackingLeafDomain, member, r.Next, nullifierPk, r.CtHash, r.View0, r.View1, r.Revision, r.ListTag}))
}

// MergeCircuit binds a ring's SPP merge output to a record only its auditor opens.
type MergeCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	OutputUtxoHash frontend.Variable
	FirstNullifier frontend.Variable
	RingProgramID  frontend.Variable
	AuditorPk      [32]frontend.Variable
	Payer          frontend.Variable
	TrackingRoot   frontend.Variable

	EphSk       [32]frontend.Variable
	OwnerKey    [32]frontend.Variable
	Mint        [32]frontend.Variable
	Amount      frontend.Variable
	NullifierPk frontend.Variable
	// The nullifier secret off ZeroNullifierPk, the private merge seed under it, SPP's proof holds it to the key.
	Seed               frontend.Variable
	OutputTreeID       frontend.Variable
	OutputRingDataHash frontend.Variable
	Tracking           TrackingRow
}

func (c *MergeCircuit) Define(api frontend.API) error {
	// 1. The cipher bounds the key and mint bytes, the owner identity and the asset read them unchecked.
	ownerPkHash := gadget.SolanaOwnerIdentityBounded(api, c.OwnerKey)
	asset := gadget.HashChain(api, shared.PackBounded(api, c.Mint[:]))
	zeroKey := api.IsZero(api.Sub(c.NullifierPk, shared.ZeroNullifierPk))
	hidden := api.Sub(1, zeroKey)
	// 2. A hidden owner cannot pay, the payer is public.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: hidden, V: api.IsZero(api.Sub(ownerPkHash, c.Payer))})
	// 3. A hidden owner's key is its row's, a zero key is not checked against any row and its owner signs in SPP.
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: hidden, A: c.Tracking.Root(api, ownerPkHash, c.NullifierPk), B: c.TrackingRoot})

	// 4. The output is the SPP merge output, the auditor rebuilds this hash from the record.
	api.AssertIsEqual(c.OutputUtxoHash, transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain: mergeshared.UtxoDomain, Owner: gadget.PoseidonHash(api, []frontend.Variable{ownerPkHash, c.NullifierPk}),
		Asset: asset, Amount: c.Amount, Blinding: mergeshared.MergeOutputBlinding(api, c.Seed, c.FirstNullifier),
		DataHash: 0, RingDataHash: c.OutputRingDataHash, RingProgramID: c.RingProgramID,
	}, c.OutputTreeID))

	// 5. The canonical encodings keep one plaintext per record, the 64-bit amount fails above its bytes.
	rc := rangecheck.New(api)
	nullifierPkBytes, seedBytes := ringgadget.FieldToBytesBEWith(api, rc, c.NullifierPk), ringgadget.FieldToBytesBEWith(api, rc, c.Seed)
	plaintext := slices.Concat(
		[]frontend.Variable{mergeRecordKindRing}, shared.Zeros(mergeRecordReserved), ringgadget.UintBytesBE(api, c.Amount, mergeAmountBytes),
		c.OwnerKey[:], c.Mint[:], nullifierPkBytes[:], seedBytes[:],
	)
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.MergeEncInfo}.SealStream(api)

	// 6. The statement names the SPP merge, the ring, the record and the owner SPP makes sign.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, slices.Concat(
		[]frontend.Variable{shared.MergeStatementDomain, c.OutputUtxoHash, c.FirstNullifier, c.RingProgramID},
		sealed.StatementFields(api),
		[]frontend.Variable{c.Payer, api.Mul(zeroKey, ownerPkHash), c.TrackingRoot},
	)))
	return nil
}
