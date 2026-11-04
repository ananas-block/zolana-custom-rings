package policy

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type PoolSubject struct {
	Member      frontend.Variable
	RecordIndex frontend.Variable
}

type RecordPoolShape struct {
	Own, Curator                 int
	OwnSubjects, CuratorSubjects int
}

type PoolEntry struct {
	Own     frontend.Variable
	Curator []frontend.Variable
}

type OwnerEntry struct {
	PoolEntry
	Tracking      frontend.Variable
	ListSalt      frontend.Variable
	OwnSalted     frontend.Variable
	CuratorSalted []frontend.Variable
}

func newPoolEntry(ownOnly bool) PoolEntry {
	entry := PoolEntry{}
	if !ownOnly {
		entry.Curator = make([]frontend.Variable, 1)
	}
	return entry
}

func newOwnerEntry(ownOnly bool) OwnerEntry {
	entry := OwnerEntry{PoolEntry: newPoolEntry(ownOnly)}
	if !ownOnly {
		entry.CuratorSalted = make([]frontend.Variable, 1)
	}
	return entry
}

func (s RecordPoolShape) validate(limits RecordPoolShape) error {
	if err := validatePoolCapacity(s.Own, s.OwnSubjects, limits.Own); err != nil {
		return err
	}
	if limits.Curator == 0 {
		if s.Curator != 0 || s.CuratorSubjects != 0 {
			return fmt.Errorf("policy own pool has curator capacity")
		}
		return nil
	}
	return validatePoolCapacity(s.Curator, s.CuratorSubjects, limits.Curator)
}

func validatePoolCapacity(records, subjects, maximum int) error {
	for _, capacity := range []int{records, subjects} {
		if capacity < 1 || capacity > maximum {
			return fmt.Errorf("policy pool capacity is invalid")
		}
	}
	return nil
}

func (e PoolEntry) validate(ownOnly bool) error {
	if len(e.Curator) != curatorEntries(ownOnly) {
		return fmt.Errorf("policy curator reference shape is invalid")
	}
	return nil
}

func (e OwnerEntry) validate(ownOnly bool) error {
	if len(e.CuratorSalted) != curatorEntries(ownOnly) {
		return fmt.Errorf("policy curator salted reference shape is invalid")
	}
	return e.PoolEntry.validate(ownOnly)
}

func curatorEntries(ownOnly bool) int {
	if ownOnly {
		return 0
	}
	return 1
}

func (p *PolicyInputs) recordCapacity(publicAssets int) RecordPoolShape {
	outputs, withdrawals := p.Outputs, len(p.Withdrawals)
	// Withdrawals settle through SPP public slots, so their assets are among at most NPublicSlots.
	withdrawalAssets := min(withdrawals, transaction.NPublicSlots)
	distinct := p.Senders + outputs + withdrawals + outputs + p.SaltedKeys
	limits := RecordPoolShape{Own: distinct + max(withdrawalAssets, publicAssets)}
	if !p.OwnOnly {
		limits.Curator = distinct + withdrawalAssets
	}
	return limits
}

func (s RecordPoolShape) withDefaults(limits RecordPoolShape) RecordPoolShape {
	if s.Own == 0 {
		s.Own = limits.Own
	}
	if s.Curator == 0 {
		s.Curator = limits.Curator
	}
	if s.OwnSubjects == 0 {
		s.OwnSubjects = s.Own
	}
	if s.CuratorSubjects == 0 {
		s.CuratorSubjects = s.Curator
	}
	return s
}

type recordQuery struct {
	active, member, index frontend.Variable
}

type pooledRecord struct {
	onList [NSources]frontend.Variable
	// mintPolicy stays packed, only an asset's reader decodes it.
	mintPolicy, withdrawalThreshold frontend.Variable
}

// Lists lead, the leaf hash still covers the whole record.
type recordColumns struct {
	width   int
	project func(record registry.Record) []frontend.Variable
}

var (
	ownColumns = recordColumns{width: 3, project: func(record registry.Record) []frontend.Variable {
		return []frontend.Variable{record.Lists, record.MintPolicy, record.WithdrawalThreshold}
	}}
	// A curator lookup reads list bits alone, every other field binds through the leaf hash only.
	curatorColumns = recordColumns{width: 1, project: func(record registry.Record) []frontend.Variable {
		return []frontend.Variable{record.Lists}
	}}
)

type pooledTable struct {
	active frontend.Variable
	table  *lookup.Table
}

type recordPool struct {
	pooledTable
	width int
}

type subjectPool struct{ pooledTable }

func openRecordPool(api frontend.API, active, root frontend.Variable, records []registry.Record, proof registry.SharedQuadProof, columns recordColumns) recordPool {
	api.AssertIsBoolean(active)
	pool := newRecordPool(api, active, columns.width)
	leaves := make([]frontend.Variable, len(records))
	for i, record := range records {
		leaves[i] = record.Hash(api)
		pool.table.Insert(append([]frontend.Variable{record.Member, record.Next}, columns.project(record)...))
	}
	proof.AssertLeavesWhen(api, active, root, leaves)
	return pool
}

func newRecordPool(api frontend.API, active frontend.Variable, width int) recordPool {
	return recordPool{pooledTable{active: active, table: lookup.New(api, 2+width)}, width}
}

// The range check bounds lists below 2^ListBits so one split exists.
func sourceLists(api frontend.API, lists frontend.Variable) [NSources]frontend.Variable {
	low, err := api.Compiler().NewHint(rangecheck.DecomposeHint, 1, NSources, NSources, lists)
	if err != nil {
		panic(err)
	}
	rangecheck.New(api).Check(api.DivUnchecked(api.Sub(lists, low[0]), 1<<NSources), registry.ListBits-NSources)
	return [NSources]frontend.Variable(api.ToBinary(low[0], NSources))
}

func decodeMintPolicy(api frontend.API, packed frontend.Variable) mintPolicyWires {
	limbs, err := api.Compiler().NewHint(rangecheck.DecomposeHint, 3, 192, 64, packed)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, 64)
	}
	base := new(big.Int).Lsh(big.NewInt(1), 64)
	api.AssertIsEqual(packed, api.Add(limbs[0], api.Mul(base, limbs[1]), api.Mul(new(big.Int).Mul(base, base), limbs[2])))
	return mintPolicyWires{threshold: limbs[2], cap: limbs[1], cosignAbove: limbs[0]}
}

func (p pooledTable) lookup(api frontend.API, query recordQuery) []frontend.Variable {
	api.AssertIsBoolean(query.active)
	abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: query.active, V: api.Sub(1, p.active)})
	return p.table.Lookup(query.index)
}

// Zeros for an inactive query or an absent member.
func (p recordPool) read(api frontend.API, query recordQuery) []frontend.Variable {
	row := p.lookup(api, query)
	present := api.IsZero(api.Sub(row[0], query.member))
	ringgadget.AssertOrderedWhen(api, api.Mul(query.active, api.Sub(1, present)), row[0], query.member, row[1])
	// An absent member reads zeros whatever its predecessor holds.
	return gated(api, api.Mul(query.active, present), row[2:])
}

func withLists(api frontend.API, columns []frontend.Variable) []frontend.Variable {
	onList := sourceLists(api, columns[0])
	return append(onList[:], columns[1:]...)
}

func pooledRecordAt(columns []frontend.Variable) pooledRecord {
	return pooledRecord{onList: [NSources]frontend.Variable(columns[:NSources]), mintPolicy: columns[NSources], withdrawalThreshold: columns[NSources+1]}
}

func gated(api frontend.API, active frontend.Variable, columns []frontend.Variable) []frontend.Variable {
	zeroed := make([]frontend.Variable, len(columns))
	for i, column := range columns {
		zeroed[i] = api.Mul(active, column)
	}
	return zeroed
}

func openSubjectPool(api frontend.API, records recordPool, subjects []PoolSubject) subjectPool {
	pool := subjectPool{pooledTable{active: records.active, table: lookup.New(api, 1+records.width)}}
	for _, subject := range subjects {
		resolved := records.read(api, recordQuery{active: records.active, member: subject.Member, index: subject.RecordIndex})
		pool.table.Insert(append([]frontend.Variable{subject.Member}, resolved...))
	}
	return pool
}

func (p subjectPool) read(api frontend.API, query recordQuery) []frontend.Variable {
	row := p.lookup(api, query)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: query.active, A: row[0], B: query.member})
	return gated(api, query.active, row[1:])
}

func (p subjectPool) resolve(api frontend.API, query recordQuery) []frontend.Variable {
	return withLists(api, p.read(api, query))
}
