// Resolves owner credentials once per member for transfer and deposit predicates.
// A live opening either authenticates the immutable credential in an SPP state
// tree or proves its address absent at the bound checkpoint. Zero members pad
// the pool. A query selects a whole authenticated row by index and member.
//
// Present and absent views can coexist for a queued enrollment under different
// proofs. Pairwise distinct live members forbid those two views inside one proof.
// The program accepts an address root only above every applicable private source
// floor, and every private owner write establishes address inclusion at its floor.
//
// Read after registry/credential.go and policy/record_pool.go.
// Read before transfer/owners.go, policy/subjects.go and deposit.go.
//
// Properties
// 1. Every present row binds its ring, owner, key and salt commitment through state inclusion.
// 2. Every absent live row authenticates a strict address gap and returns zero columns.
// 3. Live members are distinct, and active queries cannot select padding or another member.
// 4. StatementFields binds the credential owner, address root and ordered state-root table.

package policy

import (
	"errors"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
)

type CredentialOpening = registry.CredentialOpening

type Credentials struct {
	CredentialOwner frontend.Variable
	AddressRoot     frontend.Variable
	StateRoots      [][2]frontend.Variable
	Openings        []CredentialOpening
	RowEntries      []frontend.Variable
	OutputEntries   []frontend.Variable
}

type CredentialView struct {
	NullifierPk, ListTag frontend.Variable
}

type CredentialPool struct {
	subjects subjectPool
}

func NewCredentials(rows, outputs, withdrawals int) (Credentials, error) {
	capacity := rows + outputs + withdrawals
	if rows < 0 || outputs < 0 || withdrawals < 0 || capacity < 1 {
		return Credentials{}, errors.New("credential pool capacity is invalid")
	}
	return Credentials{
		StateRoots: make([][2]frontend.Variable, capacity), Openings: make([]CredentialOpening, capacity),
		RowEntries: make([]frontend.Variable, rows), OutputEntries: make([]frontend.Variable, outputs),
	}, nil
}

func (c *Credentials) ValidateCredentials(rows, outputs, withdrawals int) error {
	capacity := rows + outputs + withdrawals
	if rows < 0 || outputs < 0 || withdrawals < 0 || capacity < 1 || len(c.StateRoots) != capacity || len(c.Openings) != capacity {
		return errors.New("credential pool capacity is invalid")
	}
	if len(c.RowEntries) != rows || len(c.OutputEntries) != outputs {
		return errors.New("credentials require one reference per row and output")
	}
	return nil
}

func (c *Credentials) CredentialPoolSize() int {
	return len(c.Openings)
}

func (c *Credentials) StatementFields() []frontend.Variable {
	fields := []frontend.Variable{c.CredentialOwner, c.AddressRoot}
	for _, root := range c.StateRoots {
		fields = append(fields, root[:]...)
	}
	return fields
}

func (c *Credentials) OpenCredentials(api frontend.API, ringID frontend.Variable) CredentialPool {
	// 1. Every opening uses the same statement ring, owner and accepted root table.
	roots := registry.CredentialRoots{RingID: ringID, Owner: c.CredentialOwner, StateRoots: c.StateRoots}.Check(api)
	pool := CredentialPool{subjects: subjectPool{pooledTable{active: 1, table: lookup.New(api, 3)}}}
	for i, opening := range c.Openings {
		// 2. A live opening selects exactly one authenticated branch, while padding selects neither.
		member := opening.Leaf.Member
		active := ringgadget.IsNonZero(api, member)
		opening.Open(api, active, roots, c.AddressRoot)
		// 3. One member has one answer throughout the proof, even before its address batch applies.
		for _, earlier := range c.Openings[:i] {
			api.AssertIsEqual(api.Mul(active, IsSame(api, member, earlier.Leaf.Member)), 0)
		}
		pool.subjects.table.Insert([]frontend.Variable{member, api.Mul(opening.Present, opening.Leaf.NullifierPk), api.Mul(opening.Present, opening.Leaf.ListTag)})
	}
	return pool
}

func (p CredentialPool) Row(api frontend.API, active, member, entry frontend.Variable) CredentialView {
	api.AssertIsEqual(api.Mul(active, api.IsZero(member)), 0)
	columns := p.subjects.read(api, recordQuery{active: active, member: member, index: api.Mul(active, entry)})
	return CredentialView{NullifierPk: columns[0], ListTag: columns[1]}
}
