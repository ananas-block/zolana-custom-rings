package policy

import (
	"errors"
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
)

// Tracking opens every owner row, output owner and withdrawal owner under the frame's tracking root.
type Tracking struct {
	TrackingRoot     frontend.Variable
	TrackingRecords  []registry.TrackingRecord
	TrackingProof    registry.SharedQuadProof
	TrackingSubjects []PoolSubject
	// RowEntries and OutputEntries index TrackingSubjects.
	RowEntries    []frontend.Variable
	OutputEntries []frontend.Variable
}

// TrackingView reads zeros for an absent member, enrollment refuses a zero key so the key alone tells presence.
type TrackingView struct {
	NullifierPk, ListTag frontend.Variable
}

// NewTracking also sizes for the key's withdrawal owners, a salted list reads each owner's row.
func NewTracking(rows, outputs, withdrawals int) (Tracking, error) {
	capacity := rows + outputs + withdrawals
	proof, err := registry.NewTrackingProof(capacity)
	if err != nil {
		return Tracking{}, err
	}
	return Tracking{
		TrackingRecords:  make([]registry.TrackingRecord, capacity),
		TrackingProof:    proof,
		TrackingSubjects: make([]PoolSubject, capacity),
		RowEntries:       make([]frontend.Variable, rows),
		OutputEntries:    make([]frontend.Variable, outputs),
	}, nil
}

// Validate refuses a pool sized off the key before any wire is read.
func (t *Tracking) ValidateTracking(rows, outputs, withdrawals int) error {
	capacity := rows + outputs + withdrawals
	if len(t.RowEntries) != rows || len(t.OutputEntries) != outputs {
		return fmt.Errorf("tracking requires one reference per row and output")
	}
	if len(t.TrackingRecords) != capacity || len(t.TrackingSubjects) != capacity {
		return errors.New("tracking pool capacity is invalid")
	}
	return t.TrackingProof.Validate(capacity)
}

// TrackingPoolSize is the records and subjects the key opens.
func (t *Tracking) TrackingPoolSize() int {
	return len(t.TrackingRecords)
}

// TrackingPool answers row and output queries, a member absent from the root reads zeros.
type TrackingPool struct {
	subjects subjectPool
}

const trackingColumns = 2

func (t *Tracking) OpenTracking(api frontend.API) TrackingPool {
	records := newRecordPool(api, 1, trackingColumns)
	leaves := make([]frontend.Variable, len(t.TrackingRecords))
	for i, record := range t.TrackingRecords {
		leaves[i] = record.Hash(api)
		records.table.Insert([]frontend.Variable{record.Member, record.Next, record.NullifierPk, record.ListTag})
	}
	t.TrackingProof.AssertLeaves(api, t.TrackingRoot, leaves)
	return TrackingPool{subjects: openSubjectPool(api, records, t.TrackingSubjects)}
}

// Row reads member at entry while active is set, zeros otherwise.
func (p TrackingPool) Row(api frontend.API, active, member, entry frontend.Variable) TrackingView {
	columns := p.subjects.read(api, recordQuery{active: active, member: member, index: entry})
	return TrackingView{NullifierPk: columns[0], ListTag: columns[1]}
}
