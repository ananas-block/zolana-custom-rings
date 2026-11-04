// Rebuilds each note's commitment exactly as the shielded pool does. Ring
// proofs tie to the pool's transfer through these commitments, so any
// difference breaks the link.

package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// UtxoWires opens one transaction slot, its owner is Poseidon(OwnerPkHash, NullifierPk).
type UtxoWires struct {
	Domain        frontend.Variable
	TreeID        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

// Output is one slot's constrained opening, the wires its hash commits to beside the hash and the slot's class.
type Output struct {
	UtxoWires
	// Hash is the commitment SPP publishes or spends, a dummy's included.
	Hash frontend.Variable
	// Utxo is set on a note, Ring on a note of a ring and Exit on a note of the default ring, a dummy clears all three.
	Utxo, Ring, Exit frontend.Variable
}

// Open hashes the slot as SPP does and classifies it, so a ring proof binds the commitment SPP publishes or spends.
func (w UtxoWires) Open(api frontend.API) Output {
	utxo := api.IsZero(api.Sub(w.Domain, transaction.UtxoDomain))
	owner := api.Mul(utxo, gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk}))
	hash := transaction.UtxoHashCircuit(api, transaction.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         owner,
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	}, w.TreeID)
	// SPP holds every UTXO's ring id to 0 or the ring's on the same output hashes, AssertRingMemberOrFree in spp_transaction/shared/ring.go.
	ring := api.Mul(utxo, ringgadget.IsNonZero(api, w.RingProgramID))
	return Output{UtxoWires: w, Hash: hash, Utxo: utxo, Ring: ring, Exit: api.Sub(utxo, ring)}
}

// OpenInput opens a spent slot, an address spends nothing and reaches the proof through the address chain alone, a dummy carries nothing but its blinding.
func (w UtxoWires) OpenInput(api frontend.API) Output {
	opened := w.Open(api)
	dummy := api.IsZero(api.Sub(w.Domain, transaction.DummyDomain))
	address := api.IsZero(api.Sub(w.Domain, transaction.AddressDomain))
	api.AssertIsEqual(api.Add(opened.Utxo, dummy, address), 1)
	// Open zeroes a dummy's owner hash before the hash reads it.
	transaction.AssertWhen(api, dummy, transaction.UtxoCircuitFields{
		Domain: w.Domain, Owner: 0, Asset: w.Asset, Amount: w.Amount, Blinding: w.Blinding,
		DataHash: w.DataHash, RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}.CheckDummy(api))
	return opened
}

// UtxoHashes is utxo * hash per slot, the output list private_tx_hash chains, zero on a dummy.
func UtxoHashes(api frontend.API, outputs []Output) []frontend.Variable {
	hashes := make([]frontend.Variable, len(outputs))
	for i, out := range outputs {
		hashes[i] = api.Mul(out.Utxo, out.Hash)
	}
	return hashes
}
