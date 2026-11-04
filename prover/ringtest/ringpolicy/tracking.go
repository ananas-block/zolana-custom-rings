package ringpolicy

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

// ListSaltOf is the fixture owner's list salt, one per owner.
func ListSaltOf(t testing.TB, owner *big.Int) *big.Int {
	t.Helper()
	return ringregistry.ListSalt(t, new(big.Int).Add(owner, big.NewInt(4)))
}

// Enroll applies owner's leaf, the fields no owner predicate reads derive from it.
func Enroll(t testing.TB, tree *ringregistry.Tracking, owner, nullifierPk *big.Int) {
	t.Helper()
	derived := func(offset int64) *big.Int { return new(big.Int).Add(owner, big.NewInt(offset)) }
	tree.Apply(t, ringregistry.TrackingEntry{Member: owner, NullifierPk: nullifierPk, CtHash: derived(1), View0: derived(2), View1: derived(3), Revision: big.NewInt(1), ListTag: ringregistry.ListTag(t, ListSaltOf(t, owner))})
}

// FillPrivate opens one row per live owner subject, a padding row past them, salt zero for an owner with no tracking row.
func FillPrivate(t testing.TB, p *policy.Policy, lists *ringprivatelist.Tree, tracking *ringregistry.Tracking, senders []frontend.Variable, outputs []shared.UtxoWires) {
	t.Helper()
	seen := map[string]int{}
	var rows []privatelist.Row
	var owners []frontend.Variable
	subject := func(entry policy.PoolEntry, member frontend.Variable) {
		identity := ringtest.AsBigInt(member)
		if identity.Sign() == 0 {
			entry.Private[0] = 0
			return
		}
		index, ok := seen[identity.String()]
		if !ok {
			salt := big.NewInt(0)
			if tracking.Opening(identity).Present {
				salt = ListSaltOf(t, identity)
			}
			index = len(rows)
			seen[identity.String()] = index
			rows, owners = append(rows, lists.Row(t, identity, salt)), append(owners, member)
		}
		entry.Private[0] = index
	}
	for j, sender := range senders {
		subject(p.SenderEntries[j], sender)
	}
	for o, output := range outputs {
		subject(p.OwnerEntries[o], output.OwnerPkHash)
	}
	for i, leg := range p.Withdrawals {
		subject(p.OwnerEntries[len(outputs)+i], leg.Owner)
	}
	if len(rows) > len(p.PrivateRows) {
		t.Fatalf("private pool needs %d rows with capacity %d", len(rows), len(p.PrivateRows))
	}
	for i := range p.PrivateRows {
		p.PrivateRows[i], p.PrivateOwners[i] = ringprivatelist.PaddingRow(), 0
		if i < len(rows) {
			p.PrivateRows[i], p.PrivateOwners[i] = rows[i], owners[i]
		}
	}
}

// FillTracking opens each live member once and fills the pool cyclically.
func FillTracking(t testing.TB, target *policy.Tracking, tree *ringregistry.Tracking, rows, outputs []frontend.Variable, p *policy.Policy) {
	t.Helper()
	var (
		records     []circuitregistry.TrackingRecord
		indices     []uint64
		subjects    []policy.PoolSubject
		seenRecords = map[uint64]int{}
		seenMembers = map[string]int{}
	)
	add := func(member frontend.Variable) int {
		identity := ringtest.AsBigInt(member)
		if entry, ok := seenMembers[identity.String()]; ok {
			return entry
		}
		opening := tree.Opening(identity)
		record, ok := seenRecords[opening.Path.Index]
		if !ok {
			record = len(records)
			seenRecords[opening.Path.Index] = record
			records = append(records, opening.Record.Wires())
			indices = append(indices, opening.Path.Index)
		}
		seenMembers[identity.String()] = len(subjects)
		subjects = append(subjects, policy.PoolSubject{Member: member, RecordIndex: record})
		return len(subjects) - 1
	}
	entry := func(member frontend.Variable) frontend.Variable {
		if ringtest.AsBigInt(member).Sign() == 0 {
			return 0
		}
		return add(member)
	}
	for j, member := range rows {
		target.RowEntries[j] = entry(member)
	}
	for o, member := range outputs {
		target.OutputEntries[o] = entry(member)
	}
	if p != nil {
		for i, owner := range p.PrivateOwners {
			p.PrivateTracking[i] = entry(owner)
		}
	}
	// The sentinel fills a pool nothing live opened.
	if len(subjects) == 0 {
		add(big.NewInt(0))
	}
	if len(subjects) > len(target.TrackingSubjects) {
		t.Fatalf("tracking needs %d subjects with capacity %d", len(subjects), len(target.TrackingSubjects))
	}
	target.TrackingRoot = tree.Root()
	filled := make([]uint64, len(target.TrackingRecords))
	for i := range target.TrackingRecords {
		filled[i] = indices[i%len(indices)]
		target.TrackingRecords[i] = records[i%len(records)]
	}
	for i := range target.TrackingSubjects {
		target.TrackingSubjects[i] = subjects[i%len(subjects)]
	}
	proof, err := tree.SharedProof(filled)
	if err != nil {
		t.Fatal(err)
	}
	target.TrackingProof = proof
}
