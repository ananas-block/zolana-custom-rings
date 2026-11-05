// Reopens the slots SPP spends and the signer run the program hashed, the two facts the rail's owner
// predicate reads.
//
// SPP holds each input's owner to its own signer vector or hidden owner, under the rail of the SPP
// circuit it runs. The ring binds rail bits of its own in its statement. The owner relation repeats
// here over the ring proof's openings, and it is the constraint that ties those bits to the owners the
// rows and the policy read. A proof naming the signer rail cannot carry an owner outside the run.
//
// Read after transfer/transfer.go, shared/utxo.go. Read before transfer/owners.go, policy/screen.go.
//
// Properties:
// 1. Notes open first with none past the published input count, so spent UTXO k pairs with nullifier k.
// 2. A live input belongs to the bound ring, a default-ring input passes only on an entry key.
// 3. The run holds SignerCount members and zeros past them, its chain is the one the program hashed and zero on an empty run.
// 4. While active, every live input's owner is a counted member or the rail's private owner.

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
	// utxo * hash per slot, the list private_tx_hash chains.
	Hashes []frontend.Variable
	Count  ringgadget.Count
}

func OpenInputs(api frontend.API, inputs []shared.UtxoWires, inputCount frontend.Variable) InputSection {
	section := InputSection{Slots: make([]shared.Output, len(inputs)), Hashes: make([]frontend.Variable, len(inputs)), Count: ringgadget.SelectCount(api, inputCount, 1, len(inputs))}
	for i, input := range inputs {
		slot := input.OpenInput(api)
		// A spent note past the published count has no nullifier to bind.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Sub(1, section.Count.Active[i]), V: slot.Utxo})
		if i > 0 {
			// Twin of SPP's AssertDummiesLast, pairing spent UTXO k with nullifier k needs both.
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: slot.Utxo, V: api.Sub(1, section.Slots[i-1].Utxo)})
		}
		section.Slots[i], section.Hashes[i] = slot, api.Mul(slot.Utxo, slot.Hash)
	}
	return section
}

// AssertRingNotes holds every live input to the bound ring, a key with entry capacity also spends a default-ring note.
func (s InputSection) AssertRingNotes(api frontend.API, ringID frontend.Variable, entry bool) {
	for _, slot := range s.Slots {
		// Off an entry key the condition reads every note, so a default-ring note fails its zero ring id. The auditor stream of such a key has no evidence to open one.
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

// AssertOwners holds every live input to a counted member or to private while active is set.
func (s SignerSet) AssertOwners(api frontend.API, section InputSection, active, private frontend.Variable) {
	for _, slot := range section.Slots {
		// Either factor reads zero on a permitted owner. A zero owner would match a zero private here, AssertInputOwners refuses it for want of a row.
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(active, slot.Utxo), V: api.Mul(s.missing(api, slot.OwnerPkHash), api.Sub(slot.OwnerPkHash, private))})
	}
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
