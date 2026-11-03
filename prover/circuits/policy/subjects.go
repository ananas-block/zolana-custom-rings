package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type subjectView struct {
	// onList[i] is set when the subject is on list i+1 in the registry serving the list.
	onList [NSources]frontend.Variable
	// escrowKey is the own record's escrow key, zero for an absent member.
	escrowKey frontend.Variable
}

type subjects struct {
	sender         subjectView
	owners, assets []subjectView
	mintPolicies   []mintPolicyWires
	publicAssets   []publicAsset
}

// Rail is what the statement and the key fix about a transfer's rail, the one source of every section gate.
type Rail struct {
	// Exempt holds every public slot's gross withdrawal to its record's threshold.
	Exempt frontend.Variable
	// KeyEscrow holds every UTXO output's owner to an escrowed key.
	KeyEscrow frontend.Variable
	// Delegate is the authority rail, no outflow bound and no approval.
	Delegate frontend.Variable
	// Published is set when the statement carries every recipient identity, the confidential rails.
	Published frontend.Variable
}

// Gates switch the policy sections on, derived once from the rail and policy_hash.
type Gates struct {
	// Screened is set when policy_hash is nonzero, the table and the rules then bind.
	Screened  frontend.Variable
	Exempt    frontend.Variable
	KeyEscrow frontend.Variable
	// Outflow switches the caps and the approval, screened and off the authority rail.
	Outflow   frontend.Variable
	Published frontend.Variable
}

func (r Rail) gates(api frontend.API, policyHash frontend.Variable) Gates {
	screened := ringgadget.IsNonZero(api, policyHash)
	return Gates{Screened: screened, Exempt: r.Exempt, KeyEscrow: r.KeyEscrow, Outflow: api.Mul(screened, api.Sub(1, r.Delegate)), Published: r.Published}
}

// resolveSubjects opens one record per subject the gates activate, an inactive query reads zeros and a pool activates as the OR of its queries.
func (p *Policy) resolveSubjects(api frontend.API, table tableView, g Gates, sender frontend.Variable, payments []Payment, outputs int) subjects {
	escrowed := api.Or(g.Screened, g.KeyEscrow)
	ownActive := api.Or(escrowed, g.Exempt)
	own := openSubjectPool(api, openRecordPool(api, ownActive, p.OwnRoot, p.OwnRecords, p.OwnProof), p.OwnSubjects)
	var curator subjectPool
	curated := api.Mul(g.Screened, table.sources.anyForeign)
	if !p.OwnOnly {
		curator = openSubjectPool(api, openRecordPool(api, curated, p.CuratorRoot, p.CuratorRecords, p.CuratorProof), p.CuratorSubjects)
	}
	resolve := func(entry PoolEntry, active, member frontend.Variable) (subjectView, pooledRecord) {
		record := own.resolve(api, recordQuery{active: active, member: member, index: entry.Own})
		view := subjectView{onList: record.onList, escrowKey: record.escrowKey}
		if !p.OwnOnly {
			foreign := curator.resolve(api, recordQuery{active: api.Mul(active, curated), member: member, index: entry.Curator[0]})
			view.onList = table.sources.lists(api, record.onList, foreign.onList)
		}
		return view, record
	}
	resolved := subjects{owners: make([]subjectView, len(payments)), assets: make([]subjectView, len(payments)), mintPolicies: make([]mintPolicyWires, len(payments))}
	resolved.sender, _ = resolve(p.SenderEntry, g.Screened, sender)
	for i, pay := range payments {
		// An escrowed output owner resolves off a policy, a withdrawal owner only under one.
		ownerActive := api.Mul(pay.Active, g.Screened)
		if i < outputs {
			ownerActive = api.Mul(pay.Active, escrowed)
		}
		resolved.owners[i], _ = resolve(p.OwnerEntries[i], ownerActive, pay.Owner)
		var record pooledRecord
		resolved.assets[i], record = resolve(p.AssetEntries[i], api.Mul(pay.Active, g.Screened), pay.Asset)
		resolved.mintPolicies[i] = record.mintPolicy
	}
	for k, index := range p.PublicAssetEntries {
		asset := p.PublicAssets[k]
		// A public asset's record serves the outflow limits under a policy and the withdrawal threshold under an exemption.
		active := api.Mul(ringgadget.IsNonZero(api, asset), api.Or(g.Screened, g.Exempt))
		record := own.resolve(api, recordQuery{active: active, member: asset, index: index})
		resolved.publicAssets = append(resolved.publicAssets, publicAsset{asset: asset, active: active, policy: record.mintPolicy, withdrawalThreshold: record.withdrawalThreshold})
	}
	return resolved
}

func (p *PolicyInputs) assertEscrow(api frontend.API, keyEscrow frontend.Variable, owners []subjectView, outputs []shared.Output) {
	for o, out := range outputs {
		escrowed := api.Mul(out.Utxo, keyEscrow)
		key := registry.EscrowKey(api, out.NullifierPk, p.CtHashes[o])
		// The owner's record escrows Poseidon(nullifier_pk, ct_hash), an absent owner resolves zero and never matches.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: owners[o].escrowKey, B: key})
	}
}

func (p *PolicyInputs) assertOwnOnly(api frontend.API) {
	if !p.OwnOnly {
		return
	}
	// The own-only key reads every list from own_root, a curator source or root would be screened against the wrong registry.
	api.AssertIsEqual(p.CuratorRoot, 0)
	for _, source := range p.Sources {
		api.AssertIsEqual(source.Registry, 0)
	}
}
