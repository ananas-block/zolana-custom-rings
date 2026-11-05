// Package circuits proves a ring deposit and an anonymous ring merge.
//
// SPP's ring_deposit takes each output's Poseidon(owner_hash, blinding) as an opaque value with a public
// asset and amount, leaves the blinding's freshness to the ring and runs no proof. A depositor alone
// could therefore credit a note no auditor opens. The ring proof gives each occupied slot the opening
// record a transfer's auditor would read, and it spends nothing, so it reads no nullifier tree.
//
// No envelope key derives a deposit's blinding, so the record seals the blinding itself after a
// transfer's record. BlindingSecret stays out of the record, and CRDB keeps the result off every SPP
// output blinding. One batch shares one stream under one EphSk.
//
// The deposit statement proves the following per occupied slot of the Count it publishes.
//  1. The owner commitment SPP receives is Poseidon(Poseidon(owner, key), CRDB blinding), and the slot's
//     ciphertext seals the opening record that rebuilds it, under one CRING/dep stream.
//  2. The record's asset and amount are the statement's public cells, the program rebuilds those from
//     SPP's instruction.
//  3. A nonzero key is the owner's enrolled row's under the tracking root, a zero key leaves the owner absent.
//  4. On a policy ring the recipient and the deposited asset meet the rules under the bound roots.
//
// A padding slot carries nothing, its statement cells read zero.
//
// It proves nothing about the recipient's ciphertext a capsule also carries. Those bytes reach the
// statement only through ContextHash, a hash of the program id, the tree and the whole SPP data, and no
// constraint reads them. Delivery stays outside the circuit as on a transfer, see package audit.
//
// Read after shared/envelope.go, audit/record.go, registry/tracking.go, policy/deposit.go, transfer/owners.go.
// Read before ../ring/ring.go.
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
	DepositRecordLen = audit.OpeningRecordLen
)

// DepositCircuit binds every deposited owner commitment to a record sealed for the auditor.
type DepositCircuit struct {
	Capacity        int               `gnark:"-"`
	PublicInputHash frontend.Variable `gnark:",public"`
	ContextHash     frontend.Variable
	Count           frontend.Variable
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
		// 2. A padding slot carries no owner, nullifier key, blinding secret, asset or amount, its statement cells read zero as the program hashes them.
		for _, value := range []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.Assets[i], c.Amounts[i]} {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, active), V: value})
		}
		slots[i] = shared.Output{
			UtxoWires: shared.UtxoWires{OwnerPkHash: c.OwnerPkHashes[i], NullifierPk: c.NullifierPks[i], Asset: c.Assets[i], Amount: c.Amounts[i]},
			Utxo:      active, Ring: active, Exit: 0,
		}
		// 3. The blinding is derived in the CRDB domain, the commitment is the deposited UTXO's owner part SPP hashes into the note.
		owner := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkHashes[i], c.NullifierPks[i]})
		blinding := shared.DepositBlinding(api, c.BlindingSecrets[i])
		commitments[i] = gadget.PoseidonHash(api, []frontend.Variable{owner, blinding})
		// 4. The record seals the blinding the reader rebuilds the commitment with, and bounds a live amount below 2^64 as the comparator needs.
		plaintext = slices.Concat(plaintext, audit.OpeningRecord{RecordOpening: audit.RecordOpening{
			Live: active, Kind: api.Mul(active, audit.KindRing), Amount: c.Amounts[i], OwnerPkHash: c.OwnerPkHashes[i], NullifierPk: c.NullifierPks[i], Asset: c.Assets[i],
			OwnerKey: c.OwnerKeys[i], MintChunks: c.MintChunks[i],
		}, Secret: blinding}.Encode(api, rc))
	}
	// 5. A key off ZeroNullifierPk is its owner's row's, ZeroNullifierPk leaves its owner absent under the root. The owners read the same check as a transfer's outputs.
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
	chain := []frontend.Variable{shared.DepositStatementDomain, c.ContextHash, c.Count}
	ciphertexts := audit.SlotRegions{Stride: DepositRecordLen, Length: DepositRecordLen}.Hashes(api, sealed.Ciphertext, count.Active)
	for i, commitment := range commitments {
		chain = append(chain, api.Mul(count.Active[i], commitment), ciphertexts[i])
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
