package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type DepositScreen struct {
	Table               Table
	AssetRecords        []registry.QuadOpening
	OwnerRecords        []registry.QuadOpening
	CuratorRoot         frontend.Variable
	CuratorAssetRecords []registry.QuadOpening
	CuratorOwnerRecords []registry.QuadOpening
}

func NewDepositScreen(capacity int) DepositScreen {
	return DepositScreen{
		AssetRecords: make([]registry.QuadOpening, capacity), OwnerRecords: make([]registry.QuadOpening, capacity),
		CuratorAssetRecords: make([]registry.QuadOpening, capacity), CuratorOwnerRecords: make([]registry.QuadOpening, capacity),
	}
}

// Assert screens nothing under a zero policyHash, the program binds zero off a policy ring.
func (d DepositScreen) Assert(api frontend.API, rc frontend.Rangechecker, policyHash, ownRoot frontend.Variable, deposits []Payment) {
	// 1. A nonzero policy_hash fixes the table the rules read.
	screened := ringgadget.IsNonZero(api, policyHash)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: screened, A: policyHash, B: d.Table.hash(api)})
	table := d.Table.view(api, rc)
	// 2. Each deposited asset and recipient opens its record, or its absence, under own_root and under curator_root when a source names the curator.
	resolved := subjects{owners: make([]subjectView, len(deposits)), assets: make([]subjectView, len(deposits)), mintPolicies: make([]mintPolicyWires, len(deposits))}
	payments := make([]Payment, len(deposits))
	for i, deposit := range deposits {
		active := api.Mul(screened, deposit.Active)
		// The comparator width holds for u64 amounts only.
		rc.Check(deposit.Amount, 64)
		lists, _, mintPolicy, _ := d.AssetRecords[i].Resolve(api, active, ownRoot, deposit.Asset)
		curated, _, _, _ := d.CuratorAssetRecords[i].Resolve(api, api.Mul(active, table.sources.anyForeign), d.CuratorRoot, deposit.Asset)
		resolved.assets[i] = subjectView{onList: table.sources.lists(api, sourceLists(api, lists), sourceLists(api, curated)), escrowKey: 0}
		resolved.mintPolicies[i] = decodeMintPolicy(api, mintPolicy)
		ownerLists, _, _, _ := d.OwnerRecords[i].Resolve(api, active, ownRoot, deposit.Owner)
		curatedOwner, _, _, _ := d.CuratorOwnerRecords[i].Resolve(api, api.Mul(active, table.sources.anyForeign), d.CuratorRoot, deposit.Owner)
		resolved.owners[i] = subjectView{onList: table.sources.lists(api, sourceLists(api, ownerLists), sourceLists(api, curatedOwner)), escrowKey: 0}
		payments[i] = Payment{Owner: deposit.Owner, Asset: deposit.Asset, Amount: deposit.Amount, Active: active}
	}
	// 3. Every active owner and asset rule holds for each deposit as for a transfer output.
	assertPaymentRules(api, newComparator(rc, len(deposits)), screened, screenedRules(api, screened, table), table, resolved, payments)
}
