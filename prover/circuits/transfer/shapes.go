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
	return audit.StreamShape{InputClass: s.Inputs, Outputs: s.Outputs, Entry: s.Entry, Data: true}
}

func (s Shape) entries() int {
	if s.Entry {
		return s.Inputs
	}
	return 0
}

// ownerAddresses mirrors OWNER_ADDRESSES in key_catalog.rs, a v1 transaction's 64 addresses less SPP's 4 and the ring's 6.
const ownerAddresses = 64 - 4 - 6

// publicOwners is the distinct signers and legs one transaction can name, each signer also takes a nullifier PDA.
func (s Shape) publicOwners() int {
	return min(s.Owners, (ownerAddresses-s.Withdrawals)/2) + s.Withdrawals
}

func (s Shape) trackedWithdrawals() int {
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
