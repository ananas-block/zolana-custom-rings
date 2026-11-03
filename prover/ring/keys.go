package ring

import (
	"fmt"
	"strings"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Family is mirrored by RingCircuit in program-libs/interface/src/proof/key_catalog.rs.
type Family int

const (
	TransferConfidential Family = iota
	TransferAnonymous
	TransferAnonymousEntry
	ApplyRecords
	RegisterKey
	Deposit
	Merge
)

type Key struct {
	Circuit common.CircuitType
	Family  Family
	// Inputs counts the input slots, queued writes or merged UTXOs the key sizes.
	Inputs      int
	Outputs     int
	Withdrawals int
}

// Keys takes each shape from the package that sizes it.
var Keys = keys()

func (k Key) KeyFile() string {
	return strings.ReplaceAll(string(k.Circuit), "-", "_") + ".key"
}

func keys() []Key {
	var keys []Key
	add := func(family Family, inputs, outputs, withdrawals int) {
		key := Key{Family: family, Inputs: inputs, Outputs: outputs, Withdrawals: withdrawals}
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, shape := range transfer.ConfidentialShapes {
		add(TransferConfidential, shape.Inputs, shape.Outputs, shape.Withdrawals)
	}
	for _, shape := range transfer.AnonymousShapes {
		add(TransferAnonymous, shape.InputClass, shape.Outputs, shape.Withdrawals)
	}
	for _, shape := range transfer.EntryShapes {
		add(TransferAnonymousEntry, shape.InputClass, shape.Outputs, shape.Withdrawals)
	}
	for _, writes := range registry.ApplyWidths {
		add(ApplyRecords, writes, 0, 0)
	}
	add(RegisterKey, 0, 0, 0)
	for _, capacity := range circuits.DepositCapacities {
		add(Deposit, capacity, 0, 0)
	}
	for _, width := range circuits.MergeWidths {
		add(Merge, width, 0, 0)
	}
	return keys
}

func (k Key) confidentialShape() transfer.ConfidentialShape {
	return transfer.ConfidentialShape{Inputs: k.Inputs, Outputs: k.Outputs, Withdrawals: k.Withdrawals}
}

func (k Key) anonymousShape() transfer.AnonymousShape {
	return transfer.AnonymousShape{InputClass: k.Inputs, Outputs: k.Outputs, Withdrawals: k.Withdrawals, FullOpenings: k.Family == TransferAnonymousEntry}
}

func (k Key) circuitType() common.CircuitType {
	named := func(format string, args ...any) common.CircuitType {
		return common.CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case TransferConfidential:
		return named("transfer-confidential-%d-in%d-w%d", k.Outputs, k.Inputs, k.Withdrawals)
	case TransferAnonymous:
		return named("transfer-anonymous-%d-in%d-w%d", k.Outputs, k.Inputs, k.Withdrawals)
	case TransferAnonymousEntry:
		return named("transfer-anonymous-entry-%d-in%d-w%d", k.Outputs, k.Inputs, k.Withdrawals)
	case ApplyRecords:
		return named("apply-records-%d", k.Inputs)
	case RegisterKey:
		return named("register-key")
	case Deposit:
		return named("deposit-%d", k.Inputs)
	case Merge:
		return named("merge-v3-%d", k.Inputs)
	}
	panic(fmt.Sprintf("ring: unknown ring family %d", k.Family))
}
