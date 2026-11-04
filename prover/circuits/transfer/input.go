package transfer

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ownership stays with the rail's predicates.
type InputSection struct {
	Slots []shared.Output
	// utxo * hash per slot, one list for private_tx_hash and the evidence.
	Hashes []frontend.Variable
	Count  ringgadget.Count
}

func OpenInputs(api frontend.API, inputs []shared.UtxoWires, inputCount frontend.Variable) InputSection {
	section := InputSection{Slots: make([]shared.Output, len(inputs)), Hashes: make([]frontend.Variable, len(inputs)), Count: ringgadget.SelectCount(api, inputCount, 1, len(inputs))}
	for i, input := range inputs {
		slot := input.OpenInput(api)
		// A spent note past the published count would escape the evidence.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, section.Count.Active[i]), V: slot.Utxo})
		if i > 0 {
			// Twin of SPP's AssertDummiesLast, pairing spent UTXO k with nullifier k needs both.
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: api.Sub(1, section.Slots[i-1].Utxo)})
		}
		section.Slots[i], section.Hashes[i] = slot, api.Mul(slot.Utxo, slot.Hash)
	}
	return section
}

// AssertRingNotes holds every live input to this ring, a key with entry capacity also spends a default-ring note.
func (s InputSection) AssertRingNotes(api frontend.API, ringID frontend.Variable, entry bool) {
	for _, slot := range s.Slots {
		cond := slot.Utxo
		if entry {
			cond = slot.Ring
		}
		abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: cond, A: slot.RingProgramID, B: ringID})
	}
}

// SignerSet is the SPP owner signer run the program rebuilds, in its order.
type SignerSet struct {
	Members []frontend.Variable
	Count   ringgadget.Count
	// Chain is zero at a count of zero, the value the in-proof and authority rails bind.
	Chain frontend.Variable
}

func OpenSigners(api frontend.API, members []frontend.Variable, signerCount frontend.Variable) SignerSet {
	count := ringgadget.SelectCount(api, signerCount, 0, len(members)+1)
	for k, member := range members {
		// A member past the count would extend the chain the program hashed.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, count.Active[k]), V: member})
	}
	return SignerSet{Members: members, Count: count, Chain: api.Mul(api.Sub(1, count.OneHot[0]), gadget.HashChain4(api, members))}
}

// missing is zero exactly when owner is a counted member, a zero owner never matches padding.
func (s SignerSet) missing(api frontend.API, owner frontend.Variable) frontend.Variable {
	product := frontend.Variable(1)
	for k, member := range s.Members {
		active := s.Count.Active[k]
		product = api.Mul(product, api.Add(api.Mul(active, api.Sub(owner, member)), api.Sub(1, active)))
	}
	return product
}

// AssertOwners holds every live input to a counted member or to private while active is set, a zero private matches no owner.
func (s SignerSet) AssertOwners(api frontend.API, section InputSection, active, private frontend.Variable) {
	for _, slot := range section.Slots {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(active, slot.Utxo), V: api.Mul(s.missing(api, slot.OwnerPkHash), api.Sub(slot.OwnerPkHash, private))})
	}
}
