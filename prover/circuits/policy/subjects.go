package policy

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

type Entry struct {
	Own     registry.QuadOpening
	Curator []registry.QuadOpening
}

type subjectView struct {
	// onList[i] is set when the subject is on list i+1 in the registry serving the list.
	onList [NSources]frontend.Variable
	// escrowKey is the own record's escrow key, zero for an absent member.
	escrowKey  frontend.Variable
	mintPolicy frontend.Variable
}

type subjects struct {
	sender         subjectView
	owners, assets []subjectView
	mintPolicies   []mintPolicyWires
}

// resolveSubjects opens the sender, every UTXO output's owner and, under an asset rule, every UTXO output's asset.
func (p *Policy) resolveSubjects(api frontend.API, t tableView, sender frontend.Variable, outputs []utxoView) (subjects, error) {
	s := subjects{
		sender:       p.resolve(api, t.sources, p.SenderEntry, 1, sender),
		owners:       make([]subjectView, len(outputs)),
		assets:       make([]subjectView, len(outputs)),
		mintPolicies: make([]mintPolicyWires, len(outputs)),
	}
	for o, out := range outputs {
		s.owners[o] = p.resolve(api, t.sources, p.OwnerEntries[o], out.utxo, out.ownerPkHash)
		s.assets[o] = p.resolve(api, t.sources, p.AssetEntries[o], out.utxo, out.asset)
		s.mintPolicies[o] = decodeMintPolicy(api, s.assets[o].mintPolicy)
	}
	return s, nil
}

// resolve opens member in the own registry, and in the curator registry when a list is foreign, while cond holds.
func (p *Policy) resolve(api frontend.API, sources sourceView, e Entry, cond, member frontend.Variable) subjectView {
	// 1. The member's record, or the low record proving it absent, lies under own_root.
	own, escrowKey, mintPolicy, _ := e.Own.Resolve(api, cond, p.OwnRoot, member)
	// 2. The same holds under curator_root whenever a list reads from the curator registry.
	var curator frontend.Variable = 0
	if !p.OwnOnly {
		curator, _, _, _ = e.Curator[0].Resolve(api, api.Mul(cond, sources.anyForeign), p.CuratorRoot, member)
	}
	// 3. A record's list bitmap splits bit per list, bit i marks list i+1.
	ownBits, curatorBits := api.ToBinary(own, registry.ListBits), api.ToBinary(curator, registry.ListBits)
	view := subjectView{escrowKey: escrowKey, mintPolicy: mintPolicy}
	for i := range view.onList {
		view.onList[i] = api.Select(sources.foreign[i], curatorBits[i], ownBits[i])
	}
	return view
}

func (p *PolicyInputs) assertEscrow(api frontend.API, keyEscrow frontend.Variable, owners []subjectView, outputs []utxoView) {
	for o, out := range outputs {
		escrowed := api.Mul(out.utxo, keyEscrow)
		key := registry.EscrowKey(api, out.nullifierPk, p.Outputs[o].CtHash)
		// The owner's record escrows Poseidon(nullifier_pk, ct_hash), an absent owner resolves zero and never matches.
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: escrowed, A: owners[o].escrowKey, B: key})
	}
}

func newEntry(ownOnly bool) Entry {
	e := Entry{}
	if !ownOnly {
		e.Curator = make([]registry.QuadOpening, 1)
	}
	return e
}

func (p *PolicyInputs) assertOwnOnly(api frontend.API) {
	if !p.OwnOnly {
		return
	}
	api.AssertIsEqual(p.CuratorRoot, 0)
	for _, source := range p.Sources {
		api.AssertIsEqual(source.Registry, 0)
	}
}

type subjectResolver interface {
	resolveSubjects(frontend.API, tableView, frontend.Variable, []utxoView) (subjects, error)
	resolvePublicAsset(frontend.API, frontend.Variable, frontend.Variable, int) mintPolicyWires
}

func (p *Policy) resolvePublicAsset(api frontend.API, active, asset frontend.Variable, index int) mintPolicyWires {
	_, _, packed, _ := p.PublicAssetEntries[index].Resolve(api, active, p.OwnRoot, asset)
	return decodeMintPolicy(api, packed)
}
