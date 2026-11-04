// Proves that the auditor can open every deposited note, that each output key
// answers its owner's tracking row, and that the ring accepts the deposited token.
// A deposit spends nothing, so it reads no nullifier tree and waits on no forester.
//
// Read after shared/envelope.go, audit/record.go, registry/tracking.go, policy/deposit.go.
// Read before prover/ring/ring.go.

// Package circuits proves a ring deposit and an anonymous ring merge.
package circuits

import (
	"errors"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. The first Count of 1..Capacity owner commitments each open to the blinding and the record sealed to AuditorPk at their slot, a padding slot's plaintext is all zero.
// 2. Every blinding is Poseidon(CRDB, BlindingSecret), domain separated from every SPP output blinding.
// 3. Each occupied slot's record names the key whose Solana owner identity is its owner_pk_hash and the mint whose asset field is its asset.
// 4. A nullifier key off ZeroNullifierPk is the one its owner's row holds under TrackingRoot, ZeroNullifierPk holds its owner to no row under TrackingRoot.
// 5. Under a nonzero PolicyHash every active owner and asset rule of its table holds for each deposit on the lists its records under OwnRoot and CuratorRoot carry.

const (
	MaxDeposits = 8
	// DepositStatementVersion closes the statement, mirrored by DEPOSIT_STATEMENT_VERSION in program-libs/interface/src/instructions/deposit.rs.
	DepositStatementVersion = 4
	// DepositRecordLen is the canonical record then the blinding, mirrored by RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN.
	DepositRecordLen = MergeRecordLen
)

// DepositCircuit binds every deposited owner commitment to a record sealed for the auditor.
type DepositCircuit struct {
	Capacity        int               `gnark:"-"`
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
	Anonymous       frontend.Variable
	OwnerPkHashes   []frontend.Variable
	OwnerKeys       [][32]frontend.Variable
	NullifierPks    []frontend.Variable
	BlindingSecrets []frontend.Variable
	EphSk           [32]frontend.Variable
	AuditorPk       [32]frontend.Variable
	TrackingRoot    frontend.Variable
	Tracking        []registry.TrackingOpening
	OwnRoot         frontend.Variable
	PolicyHash      frontend.Variable
	// Each asset is SPP's asset field of its deposit's group.
	Assets     []frontend.Variable
	Amounts    []frontend.Variable
	MintChunks [][2]frontend.Variable
	policy.DepositScreen
}

var DepositCapacities = []int{1, 2, 4, 8}

func NewDepositCircuit(capacity int) (*DepositCircuit, error) {
	if err := shared.ValidateWidth("deposit", capacity, DepositCapacities); err != nil {
		return nil, err
	}
	return &DepositCircuit{
		Capacity: capacity, OwnerPkHashes: make([]frontend.Variable, capacity), OwnerKeys: make([][32]frontend.Variable, capacity), NullifierPks: make([]frontend.Variable, capacity), BlindingSecrets: make([]frontend.Variable, capacity), Tracking: make([]registry.TrackingOpening, capacity),
		Assets: make([]frontend.Variable, capacity), Amounts: make([]frontend.Variable, capacity), MintChunks: make([][2]frontend.Variable, capacity), DepositScreen: policy.NewDepositScreen(capacity),
	}, nil
}

func (c *DepositCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		shared.ValidateWidth("deposit", c.Capacity, DepositCapacities),
		shared.ValidateLength("deposit", "owner", len(c.OwnerPkHashes), c.Capacity),
		shared.ValidateLength("deposit", "owner key", len(c.OwnerKeys), c.Capacity),
		shared.ValidateLength("deposit", "nullifier key", len(c.NullifierPks), c.Capacity),
		shared.ValidateLength("deposit", "blinding secret", len(c.BlindingSecrets), c.Capacity),
		shared.ValidateLength("deposit", "tracking opening", len(c.Tracking), c.Capacity),
		shared.ValidateLength("deposit", "asset", len(c.Assets), c.Capacity),
		shared.ValidateLength("deposit", "amount", len(c.Amounts), c.Capacity),
		shared.ValidateLength("deposit", "mint", len(c.MintChunks), c.Capacity),
		shared.ValidateLength("deposit", "asset record", len(c.AssetRecords), c.Capacity),
		shared.ValidateLength("deposit", "curator asset record", len(c.CuratorAssetRecords), c.Capacity),
		shared.ValidateLength("deposit", "owner record", len(c.OwnerRecords), c.Capacity),
		shared.ValidateLength("deposit", "curator owner record", len(c.CuratorOwnerRecords), c.Capacity),
	); err != nil {
		return err
	}
	// 1. Count selects 1..Capacity occupied slots, DepositPublicInput::hash builds the flag as 0 or 1.
	count := ringgadget.SelectCount(api, c.Count, 1, c.Capacity)
	rc := rangecheck.New(api)
	commitments := make([]frontend.Variable, c.Capacity)
	var plaintext []frontend.Variable
	deposits := make([]policy.Payment, c.Capacity)
	for i := range commitments {
		active := count.Active[i]
		// 2. A padding slot carries no owner, nullifier key, blinding secret, asset or amount.
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.Assets[i], c.Amounts[i]} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: value})
		}
		// 3. A key off ZeroNullifierPk is its owner's row's, ZeroNullifierPk leaves its owner absent under the root.
		c.assertOutputKey(api, i, active)
		// 4. The blinding is derived in the CRDB domain, the commitment is the deposited UTXO's owner part.
		owner := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		blinding := shared.DepositBlinding(api, c.BlindingSecrets[i])
		commitments[i] = gadget.PoseidonHash(api, []frontend.Variable{owner, blinding})
		// 5. The record seals the blinding the reader rebuilds the commitment with.
		record := audit.RecordOpening{
			Live: active, Kind: api.Mul(active, audit.KindRing), Amount: c.Amounts[i], OwnerPkHash: c.OwnerPkHashes[i], NullifierPk: c.NullifierPks[i], Asset: c.Assets[i],
			OwnerKey: c.OwnerKeys[i], MintChunks: c.MintChunks[i],
		}.Encode(api, rc)
		blindingBytes := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(active, blinding))
		plaintext = slices.Concat(plaintext, record, blindingBytes[:])
		deposits[i] = policy.Payment{Owner: c.OwnerPkHashes[i], Asset: c.Assets[i], Amount: c.Amounts[i], Active: active}
	}
	// 6. On a policy ring every recipient and deposited asset meets the rules under the bound roots.
	c.DepositScreen.Assert(api, rc, c.PolicyHash, c.OwnRoot, deposits)
	// 7. The statement binds each commitment SPP receives to the ciphertext the auditor opens, one CRING/dep1 stream puts slot i at counter 2 + 9i.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.DepositEncInfo}.SealStream(api)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, c.statement(api, count, commitments, sealed)))
	return nil
}

func (c *DepositCircuit) assertOutputKey(api frontend.API, i int, active frontend.Variable) {
	enrolled := api.Mul(active, api.Sub(1, api.IsZero(api.Sub(c.NullifierPks[i], shared.ZeroNullifierPk))))
	row := c.Tracking[i].Resolve(api, active, c.TrackingRoot, c.OwnerPkHashes[i])
	api.AssertIsEqual(row.Present, enrolled)
	api.AssertIsEqual(row.NullifierPk, api.Mul(enrolled, c.NullifierPks[i]))
}

// statement mirrors DepositPublicInput::elements in program-libs/interface/src/instructions/deposit.rs.
func (c *DepositCircuit) statement(api frontend.API, count ringgadget.Count, commitments []frontend.Variable, sealed shared.Sealed) []frontend.Variable {
	chain := []frontend.Variable{shared.DepositStatementDomain, c.ContextHash, c.Count, c.Anonymous}
	for i, commitment := range commitments {
		ciphertext := gadget.HashBoundedBytes(api, sealed.Ciphertext[i*DepositRecordLen:(i+1)*DepositRecordLen])
		chain = append(chain, api.Mul(count.Active[i], commitment), api.Mul(count.Active[i], ciphertext))
	}
	// The public statement keeps all eight pairs. Missing slots are constants.
	for i := len(commitments); i < MaxDeposits; i++ {
		chain = append(chain, 0, 0)
	}
	chain = slices.Concat(chain, sealed.Auditor, sealed.Eph, []frontend.Variable{c.TrackingRoot, c.OwnRoot, c.CuratorRoot, c.PolicyHash})
	for i := range MaxDeposits {
		if i < len(c.Assets) {
			chain = append(chain, c.Assets[i], c.Amounts[i])
		} else {
			chain = append(chain, 0, 0)
		}
	}
	return append(chain, DepositStatementVersion)
}
