// Sizes a transfer key. Each axis bounds what a key can prove and never what it checks, a transfer
// past an axis needs a larger key and passes no predicate on a smaller one.
//
// Read after transfer/transfer.go. Read before prover/ring/keys.go.
//
// Properties:
// 1. Every shape a key compiles from is a row of TRANSFER_SHAPES, the program selects its verifying key by that row.
// 2. A wide key fits a public and a salted record for each distinct owner one transaction can name, a narrow key fits a public record for each.

package transfer

import (
	"fmt"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
)

// Shape sizes a key, Inputs also bounds the signers it can bind.
type Shape struct {
	Inputs, Outputs, Withdrawals, Owners int
	Entry                                bool
	// Wide fits a salted and a public record per owner.
	Wide bool
}

// Shapes mirrors TRANSFER_SHAPES in program-libs/interface/src/proof/key_catalog.rs.
var Shapes = [...]Shape{
	{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4},
	{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4},
	{Inputs: 16, Outputs: 8, Withdrawals: 4, Owners: 4},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5},
	{Inputs: 24, Outputs: 8, Withdrawals: 32, Owners: 24, Wide: true},
	{Inputs: 5, Outputs: 16, Withdrawals: 8, Owners: 5, Wide: true},
	{Inputs: 8, Outputs: 16, Withdrawals: 8, Owners: 8, Wide: true},
	{Inputs: 49, Outputs: 2, Withdrawals: 4, Owners: 12, Wide: true},
	{Inputs: 8, Outputs: 4, Withdrawals: 4, Owners: 8, Entry: true, Wide: true},
	{Inputs: 2, Outputs: 8, Withdrawals: 4, Owners: 2, Entry: true, Wide: true},
	{Inputs: 4, Outputs: 8, Withdrawals: 4, Owners: 4, Entry: true, Wide: true},
	{Inputs: 24, Outputs: 2, Withdrawals: 32, Owners: 12, Entry: true, Wide: true},
}

func (s Shape) String() string {
	family := "transfer"
	switch {
	case s.Entry:
		family = "transfer_entry"
	case s.Wide:
		family = "transfer_wide"
	}
	return fmt.Sprintf("custom_ring_%s_%d_in%d_w%d_s%d", family, s.Outputs, s.Inputs, s.Withdrawals, s.Owners)
}

// Stream compiles the tails into every key, a clear has_data transmits none.
func (s Shape) Stream() audit.StreamShape {
	return audit.StreamShape{InputClass: s.Inputs, Outputs: s.Outputs, Entry: s.Entry}
}

func (s Shape) entries() int {
	if s.Entry {
		return s.Inputs
	}
	return 0
}

// rowAddresses mirrors MAX_TRANSACTION_ADDRESSES less SPP_ADDRESSES and RING_ADDRESSES in key_catalog.rs.
const rowAddresses = 64 - 4 - 5

// rowAuthorization mirrors RowAuthorization in key_catalog.rs.
type rowAuthorization struct {
	// unsignedRows sign outside the owner run and take their nullifier PDA alone.
	unsignedRows int
	// hiddenExit holds every withdrawal to one destination.
	hiddenExit bool
	enters     bool
}

var rowAuthorizations = [...]rowAuthorization{
	{unsignedRows: 0, enters: true},
	{unsignedRows: 1, enters: false},
	{unsignedRows: 1, hiddenExit: true, enters: true},
}

// ownerRows mirrors TransferAddresses::owner_rows with no co-signer and shared credential trees.
func (a rowAuthorization) ownerRows(nInputs, legs int) int {
	return max(rowAddresses-nInputs-legs, 0) + a.unsignedRows
}

func (a rowAuthorization) legOwners(legs int) int {
	if a.hiddenExit {
		return min(legs, 1)
	}
	return legs
}

// publicOwners mirrors TransferShape::public_owners, each row spending one note.
func (s Shape) publicOwners() int {
	most := 0
	for _, authorization := range rowAuthorizations {
		if s.Entry && !authorization.enters {
			continue
		}
		for legs := 0; legs <= s.Withdrawals; legs++ {
			rows := s.Owners
			for rows > 0 && rows > authorization.ownerRows(rows, legs) {
				rows--
			}
			most = max(most, rows+authorization.legOwners(legs))
		}
	}
	return most
}

func (s Shape) credentialWithdrawals() int {
	if !s.Wide {
		return 0
	}
	return s.publicOwners() - s.Owners
}

// saltedKeys fits a public and a salted record per distinct owner in one pool.
func (s Shape) saltedKeys() int {
	if !s.Wide {
		return 0
	}
	return 2*s.publicOwners() + s.Outputs - s.Owners - s.Withdrawals
}
