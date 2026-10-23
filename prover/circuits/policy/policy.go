// Package policy proves a custom ring's policy over a transaction SPP proves.
package policy

import (
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties:
// 1. The rules read the policy table the program validated and hashed into policy_hash.
// 2. The outputs are the ones SPP settles under the private_tx_hash its proof binds.
// 3. One sender, the owner signer of a confidential ring, the sender an anonymous ring's commitment hides, or the one member a delegate move spends.
// 4. Every enabled rule holds for the sender and for every live output owner and asset on the lists their records carry, unless an amount guard exempts it.
// 5. On the member key every limit row's outflow is never negative and within its cap, and approval_required is set exactly when one passes its co-sign bound.
// 6. Under key escrow every UTXO output's owner record escrows the output's nullifier key.

type Policy struct {
	PrivateTxHash frontend.Variable
	PolicyHash    frontend.Variable
	RingProgramID frontend.Variable
	OwnRoot       frontend.Variable
	CuratorRoot   frontend.Variable
	PublicAssets  [transaction.NPublicSlots]frontend.Variable
	// PublicAmounts are SPP's signed nets, a withdrawal enters as the field negation of its amount.
	PublicAmounts [transaction.NPublicSlots]frontend.Variable
	Table

	AddressChain      frontend.Variable
	PrivateTxBlinding frontend.Variable
	Outputs           []OutputWires
	// Read on an anonymous ring and on the delegate key, free on a confidential ring.
	SenderPkHash frontend.Variable

	SenderEntry Entry
	// OwnerEntries[o] and AssetEntries[o] open output o's owner and asset.
	OwnerEntries []Entry
	AssetEntries []Entry
}

type railValues struct {
	// anonymous is the member key's mode bit, absent from the delegate statement.
	anonymous                           []frontend.Variable
	approvalRequired, keyEscrow, sender frontend.Variable
}

func newPolicy(outputs int) Policy {
	return Policy{
		Outputs:      make([]OutputWires, outputs),
		OwnerEntries: make([]Entry, outputs),
		AssetEntries: make([]Entry, outputs),
	}
}

// validate checks the slices against the shape a constructor sizes, before a step indexes them.
func (p *Policy) validate() error {
	outputs, owners, assets := len(p.Outputs), len(p.OwnerEntries), len(p.AssetEntries)
	if outputs == 0 || owners != outputs || assets != outputs {
		return fmt.Errorf("policy: %d outputs need one owner and one asset entry each, got %d and %d", outputs, owners, assets)
	}
	return nil
}

// statement is the policy preimage, mirrored by PolicyStatement::elements in program-libs/interface/src/statement.rs.
//
//	CRPO, private_tx_hash, policy_hash, ring_id, anonymous on the member key only, approval_required,
//	key_escrow, own_root, curator_root, sender, asset_k and amount_k per public slot
func (p *Policy) statement(rail railValues) []frontend.Variable {
	fields := []frontend.Variable{shared.PolicyStatementDomain, p.PrivateTxHash, p.PolicyHash, p.RingProgramID}
	fields = append(fields, rail.anonymous...)
	fields = append(fields, rail.approvalRequired, rail.keyEscrow, p.OwnRoot, p.CuratorRoot, rail.sender)
	for k := range p.PublicAssets {
		fields = append(fields, p.PublicAssets[k], p.PublicAmounts[k])
	}
	return fields
}

func bindStatement(api frontend.API, publicInputHash frontend.Variable, statement []frontend.Variable) {
	// The one public input fixes every statement value the steps read to the ones the program rebuilds.
	api.AssertIsEqual(publicInputHash, gadget.HashChain4(api, statement))
}
