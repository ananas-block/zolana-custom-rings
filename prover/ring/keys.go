package ring

import (
	"fmt"
	"strings"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Family is mirrored by RingCircuit in program-libs/interface/src/proof/key_catalog.rs.
type Family int

const (
	TransferConfidential Family = iota
	TransferConfidentialEntry
	TransferAnonymous
	TransferAnonymousEntry
	ApplyRecords
	ApplyEnrollments
	ApplyPrivateList
	RegisterKey
	Deposit
	Merge
)

type Key struct {
	Circuit common.CircuitType
	Family  Family
	// Inputs counts the input slots or queued writes the key sizes.
	Inputs      int
	Outputs     int
	Withdrawals int
	// Owners counts a transfer key's owner rows, Data adds its tails, Private its private rows.
	Owners, Private int
	Data            bool
}

// Keys takes each shape from the package that sizes it.
var Keys = keys()

func (k Key) KeyFile() string {
	return strings.ReplaceAll(string(k.Circuit), "-", "_") + ".key"
}

func keys() []Key {
	var keys []Key
	add := func(key Key) {
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, shape := range transfer.ConfidentialShapes {
		add(Key{Family: TransferConfidential, Inputs: shape.Inputs, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Owners: shape.Owners, Data: shape.Data, Private: shape.Private})
	}
	for _, shape := range transfer.ConfidentialEntryShapes {
		add(Key{Family: TransferConfidentialEntry, Inputs: shape.Inputs, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Owners: shape.Owners, Data: shape.Data, Private: shape.Private})
	}
	for _, shape := range transfer.AnonymousShapes {
		add(Key{Family: TransferAnonymous, Inputs: shape.InputClass, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Owners: shape.Owners, Data: shape.Data, Private: shape.Private})
	}
	for _, shape := range transfer.EntryShapes {
		add(Key{Family: TransferAnonymousEntry, Inputs: shape.InputClass, Outputs: shape.Outputs, Withdrawals: shape.Withdrawals, Owners: shape.Owners, Data: shape.Data, Private: shape.Private})
	}
	for _, writes := range registry.ApplyWidths {
		add(Key{Family: ApplyRecords, Inputs: writes})
	}
	for _, writes := range registry.ApplyWidths {
		add(Key{Family: ApplyEnrollments, Inputs: writes})
	}
	for _, writes := range privatelist.ApplyWidths {
		add(Key{Family: ApplyPrivateList, Inputs: writes})
	}
	add(Key{Family: RegisterKey})
	for _, capacity := range circuits.DepositCapacities {
		add(Key{Family: Deposit, Inputs: capacity})
	}
	add(Key{Family: Merge})
	return keys
}

func (k Key) confidentialShape() transfer.ConfidentialShape {
	return transfer.ConfidentialShape{Inputs: k.Inputs, Outputs: k.Outputs, Withdrawals: k.Withdrawals, Owners: k.Owners, Private: k.Private, Entry: k.Family == TransferConfidentialEntry, Data: k.Data}
}

func (k Key) anonymousShape() transfer.AnonymousShape {
	return transfer.AnonymousShape{InputClass: k.Inputs, Outputs: k.Outputs, Withdrawals: k.Withdrawals, Owners: k.Owners, Private: k.Private, Entry: k.Family == TransferAnonymousEntry, Data: k.Data}
}

func (k Key) suffix() string {
	switch {
	case k.Data:
		return "-data"
	case k.Private > 0:
		return fmt.Sprintf("-p%d", k.Private)
	}
	return ""
}

func (k Key) circuitType() common.CircuitType {
	named := func(format string, args ...any) common.CircuitType {
		return common.CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case TransferConfidential:
		return named("transfer-confidential-%d-in%d-w%d-s%d%s", k.Outputs, k.Inputs, k.Withdrawals, k.Owners, k.suffix())
	case TransferConfidentialEntry:
		return named("transfer-confidential-entry-%d-in%d-w%d-s%d%s", k.Outputs, k.Inputs, k.Withdrawals, k.Owners, k.suffix())
	case TransferAnonymous:
		return named("transfer-anonymous-%d-in%d-w%d-s%d%s", k.Outputs, k.Inputs, k.Withdrawals, k.Owners, k.suffix())
	case TransferAnonymousEntry:
		return named("transfer-anonymous-entry-%d-in%d-w%d-s%d%s", k.Outputs, k.Inputs, k.Withdrawals, k.Owners, k.suffix())
	case ApplyRecords:
		return named("apply-records-%d", k.Inputs)
	case ApplyEnrollments:
		return named("apply-enrollments-%d", k.Inputs)
	case ApplyPrivateList:
		return named("apply-private-list-%d", k.Inputs)
	case RegisterKey:
		return named("register-key")
	case Deposit:
		return named("deposit-%d", k.Inputs)
	case Merge:
		return named("merge-v4")
	}
	panic(fmt.Sprintf("ring: unknown ring family %d", k.Family))
}
