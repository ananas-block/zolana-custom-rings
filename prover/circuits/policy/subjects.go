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
	// addressHash is the own record's bound address, zero for an absent member.
	addressHash frontend.Variable
}

type subjects struct {
	senders        []subjectView
	liveSenders    []frontend.Variable
	owners, assets []subjectView
	mintPolicies   []mintPolicyWires
	publicAssets   []publicAsset
}

// Rail is what the statement and the key fix about a transfer's rail, the one source of every section gate.
type Rail struct {
	// ThresholdsActive is set on a ring with an own policy registry off the authority rail, independent of policy_hash.
	ThresholdsActive frontend.Variable
	// KeyEscrow holds every UTXO output's owner to an escrowed key.
	KeyEscrow frontend.Variable
	// Delegate is the authority rail, it bypasses the rules, the caps and the approval.
	Delegate frontend.Variable
	// Published is set when the statement carries every recipient identity, the confidential rails.
	Published frontend.Variable
	// Delivery opens the sender's and each output owner's row off a policy, the anonymous rails bind addresses on every ring.
	Delivery frontend.Variable
}

// Gates switch the policy sections on, derived once from the rail and policy_hash.
type Gates struct {
	// Screened is set when policy_hash is nonzero off the authority rail, the table and the rules then bind.
	Screened  frontend.Variable
	KeyEscrow frontend.Variable
	// Outflow switches the caps, the approval mask and the own root read of both.
	Outflow frontend.Variable
	// Rows holds the owner rows ascending, off the authority rail.
	Rows      frontend.Variable
	Published frontend.Variable
	Delivery  frontend.Variable
}

func (r Rail) Gates(api frontend.API, policyHash frontend.Variable) Gates {
	// The authority rail reads a zero own root, the bit would leave its proof unsolvable.
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: r.Delegate, V: r.ThresholdsActive})
	offAuthority := api.Sub(1, r.Delegate)
	return Gates{
		Screened:  api.Mul(ringgadget.IsNonZero(api, policyHash), offAuthority),
		KeyEscrow: r.KeyEscrow,
		Outflow:   r.ThresholdsActive,
		Rows:      offAuthority,
		Published: r.Published,
		Delivery:  r.Delivery,
	}
}

// resolveSubjects opens one record per subject the gates activate, an inactive query reads zeros and a pool activates as the OR of its queries.
func (p *Policy) resolveSubjects(api frontend.API, table tableView, g Gates, senders []frontend.Variable, payments []Payment, escrows []frontend.Variable) subjects {
	ownActive := ringgadget.IsAny(api, g.Screened, g.KeyEscrow, g.Outflow, g.Delivery)
	own := openSubjectPool(api, openRecordPool(api, ownActive, p.OwnRoot, p.OwnRecords, p.OwnProof, ownColumns), p.OwnSubjects)
	var curator subjectPool
	curated := api.Mul(g.Screened, table.sources.anyForeign)
	if !p.OwnOnly {
		curator = openSubjectPool(api, openRecordPool(api, curated, p.CuratorRoot, p.CuratorRecords, p.CuratorProof, curatorColumns), p.CuratorSubjects)
	}
	resolve := func(entry PoolEntry, active, member frontend.Variable) (subjectView, pooledRecord) {
		record := pooledRecordAt(own.resolve(api, recordQuery{active: active, member: member, index: entry.Own}))
		view := subjectView{onList: record.onList, escrowKey: record.escrowKey, addressHash: record.addressHash}
		if !p.OwnOnly {
			foreign := curator.resolve(api, recordQuery{active: api.Mul(active, curated), member: member, index: entry.Curator[0]})
			view.onList = table.sources.lists(api, record.onList, [NSources]frontend.Variable(foreign))
		}
		return view, record
	}
	resolved := subjects{owners: make([]subjectView, len(payments)), assets: make([]subjectView, len(payments)), mintPolicies: make([]mintPolicyWires, len(payments))}
	resolved.senders, resolved.liveSenders = make([]subjectView, len(senders)), make([]frontend.Variable, len(senders))
	for j, sender := range senders {
		// A zero identity pads the list and carries no rule.
		resolved.liveSenders[j] = ringgadget.IsNonZero(api, sender)
		active := api.Mul(g.Screened, resolved.liveSenders[j])
		if j == 0 {
			// Delivery reads the first sender's bound address off a policy.
			active = api.Or(active, g.Delivery)
		}
		resolved.senders[j], _ = resolve(p.SenderEntries[j], active, sender)
	}
	delivered := api.Or(g.Screened, g.Delivery)
	// A mint record serves the rules under a policy and the thresholds on a ring with an own registry.
	mintRead := api.Or(g.Screened, g.Outflow)
	for i, pay := range payments {
		// A withdrawal owner resolves only under a policy.
		ownerActive := api.Mul(pay.Active, g.Screened)
		if i < len(escrows) {
			// An escrowed output owner and a delivered output owner resolve off a policy.
			ownerActive = api.Or(api.Mul(pay.Active, delivered), escrows[i])
		}
		resolved.owners[i], _ = resolve(p.OwnerEntries[i], ownerActive, pay.Owner)
		var record pooledRecord
		resolved.assets[i], record = resolve(p.AssetEntries[i], api.Mul(pay.Active, mintRead), pay.Asset)
		resolved.mintPolicies[i] = record.mintPolicy
	}
	for k, index := range p.PublicAssetEntries {
		asset := p.PublicAssets[k]
		active := api.Mul(ringgadget.IsNonZero(api, asset), mintRead)
		record := pooledRecordAt(own.resolve(api, recordQuery{active: active, member: asset, index: index}))
		resolved.publicAssets = append(resolved.publicAssets, publicAsset{asset: asset, active: active, policy: record.mintPolicy, withdrawalThreshold: record.withdrawalThreshold})
	}
	return resolved
}

func escrowsOwed(api frontend.API, keyEscrow frontend.Variable, outputs []shared.Output) []frontend.Variable {
	owed := make([]frontend.Variable, len(outputs))
	for o, out := range outputs {
		owed[o] = shared.EscrowOwed(api, api.Mul(out.Utxo, keyEscrow), out.NullifierPk)
	}
	return owed
}

func (p *PolicyInputs) assertEscrow(api frontend.API, escrows []frontend.Variable, owners []subjectView, outputs []shared.Output) {
	for o, out := range outputs {
		key := registry.EscrowKey(api, out.NullifierPk, p.CtHashes[o])
		// The owner's record escrows Poseidon(nullifier_pk, ct_hash), an absent owner resolves zero and never matches.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrows[o], A: owners[o].escrowKey, B: key})
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
