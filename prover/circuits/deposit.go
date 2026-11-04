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
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

const (
	MaxDeposits = 8
	// DepositRecordLen is the canonical record then the blinding, mirrored by RING_DEPOSIT_AUDIT_CIPHERTEXT_LEN.
	DepositRecordLen = MergeRecordLen
)

// DepositCircuit binds every deposited owner commitment to a record sealed for the auditor, it spends nothing and reads no nullifier tree.
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
	// Each asset is SPP's asset field of its deposit's group.
	Assets     []frontend.Variable
	Amounts    []frontend.Variable
	MintChunks [][2]frontend.Variable
	policy.Tracking
	policy.Policy
}

var DepositCapacities = []int{1, 2, 4, 8}

func NewDepositCircuit(capacity int) (*DepositCircuit, error) {
	if err := shared.ValidateWidth("deposit", capacity, DepositCapacities); err != nil {
		return nil, err
	}
	screen, err := policy.NewDepositPolicy(capacity, depositSaltedKeys(capacity))
	if err != nil {
		return nil, err
	}
	tracking, err := policy.NewTracking(0, capacity, 0)
	if err != nil {
		return nil, err
	}
	return &DepositCircuit{
		Capacity: capacity, OwnerPkHashes: make([]frontend.Variable, capacity), OwnerKeys: make([][32]frontend.Variable, capacity), NullifierPks: make([]frontend.Variable, capacity), BlindingSecrets: make([]frontend.Variable, capacity),
		Assets: make([]frontend.Variable, capacity), Amounts: make([]frontend.Variable, capacity), MintChunks: make([][2]frontend.Variable, capacity), Tracking: tracking, Policy: screen,
	}, nil
}

// depositSaltedKeys fits a public and a salted record per recipient on the widest key, a deposit past a narrower key's pools moves to a wider one.
func depositSaltedKeys(capacity int) int {
	if capacity == MaxDeposits {
		return capacity
	}
	return 0
}

func (c *DepositCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		shared.ValidateWidth("deposit", c.Capacity, DepositCapacities),
		shared.ValidateLength("deposit", "owner", len(c.OwnerPkHashes), c.Capacity),
		shared.ValidateLength("deposit", "owner key", len(c.OwnerKeys), c.Capacity),
		shared.ValidateLength("deposit", "nullifier key", len(c.NullifierPks), c.Capacity),
		shared.ValidateLength("deposit", "blinding secret", len(c.BlindingSecrets), c.Capacity),
		shared.ValidateLength("deposit", "asset", len(c.Assets), c.Capacity),
		shared.ValidateLength("deposit", "amount", len(c.Amounts), c.Capacity),
		shared.ValidateLength("deposit", "mint", len(c.MintChunks), c.Capacity),
		shared.ValidateLength("deposit", "payment", c.Policy.Outputs, c.Capacity),
		c.Validate(0),
		c.ValidateTracking(0, c.Capacity, 0),
	); err != nil {
		return err
	}
	// 1. Count selects 1..Capacity occupied slots, DepositPublicInput::hash builds the flag as 0 or 1.
	count := ringgadget.SelectCount(api, c.Count, 1, c.Capacity)
	rc := rangecheck.New(api)
	commitments := make([]frontend.Variable, c.Capacity)
	var plaintext []frontend.Variable
	slots := make([]shared.Output, c.Capacity)
	for i := range slots {
		active := count.Active[i]
		// 2. A padding slot carries no owner, nullifier key, blinding secret, asset or amount.
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.Assets[i], c.Amounts[i]} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: value})
		}
		slots[i] = shared.Output{
			UtxoWires: shared.UtxoWires{OwnerPkHash: c.OwnerPkHashes[i], NullifierPk: c.NullifierPks[i], Asset: c.Assets[i], Amount: c.Amounts[i]},
			Utxo:      active, Ring: active, Exit: 0,
		}
		// 3. The blinding is derived in the CRDB domain, the commitment is the deposited UTXO's owner part.
		owner := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		blinding := shared.DepositBlinding(api, c.BlindingSecrets[i])
		commitments[i] = gadget.PoseidonHash(api, []frontend.Variable{owner, blinding})
		// 4. The record seals the blinding the reader rebuilds the commitment with, and bounds a live amount below 2^64 as the comparator needs.
		record := audit.RecordOpening{
			Live: active, Kind: api.Mul(active, audit.KindRing), Amount: c.Amounts[i], OwnerPkHash: c.OwnerPkHashes[i], NullifierPk: c.NullifierPks[i], Asset: c.Assets[i],
			OwnerKey: c.OwnerKeys[i], MintChunks: c.MintChunks[i],
		}.Encode(api, rc)
		blindingBytes := ringgadget.FieldToBytesBEWith(api, rc, api.Mul(active, blinding))
		plaintext = slices.Concat(plaintext, record, blindingBytes[:])
	}
	// 5. A key off ZeroNullifierPk is its owner's row's, ZeroNullifierPk leaves its owner absent under the root.
	tracking := c.OpenTracking(api)
	transfer.AssertOutputOwners(api, tracking, slots, c.OutputEntries)
	// 6. On a policy ring every recipient and deposited asset meets the rules under the bound roots.
	c.ScreenDeposit(api, rc, tracking, slots)
	// 7. The statement binds each commitment SPP receives to the ciphertext the auditor opens, one CRING/dep stream puts slot i at counter 2 + 9i.
	sealed := shared.Envelope{Plaintext: plaintext, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Info: shared.DepositEncInfo}.SealStream(api)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(api, count, commitments, sealed)))
	return nil
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
	return chain
}
