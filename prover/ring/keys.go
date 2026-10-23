package ring

import (
	"fmt"
	"slices"
	"strings"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// Family is mirrored by RingCircuit in program-libs/interface/src/key_catalog.rs.
type Family int

const (
	PackedAudit Family = iota
	DeliveredAudit
	AnonymousAudit
	AnonymousEntryAudit
	MemberPolicy
	DelegatePolicy
	ApplyRecords
	RegisterKey
	Deposit
	AnonymousMerge
)

type Key struct {
	Circuit common.CircuitType
	Family  Family
	// Inputs counts the input slots, queued writes or merged UTXOs the key sizes.
	Inputs  int
	Outputs int
}

// Keys takes each shape from the package that sizes it, one delegate key per SPP ring-authority key.
var Keys = keys()

func (k Key) KeyFile() string {
	return strings.ReplaceAll(string(k.Circuit), "-", "_") + ".key"
}

func keys() []Key {
	var keys []Key
	add := func(family Family, inputs, outputs int) {
		key := Key{Family: family, Inputs: inputs, Outputs: outputs}
		key.Circuit = key.circuitType()
		keys = append(keys, key)
	}
	for _, outputs := range audit.PackedAuditCapacities {
		add(PackedAudit, 0, outputs)
	}
	for _, outputs := range audit.DeliveredAuditCapacities {
		add(DeliveredAudit, 0, outputs)
	}
	for _, shape := range audit.AnonymousAuditShapes {
		add(AnonymousAudit, shape.InputClass, shape.Outputs)
	}
	for _, shape := range audit.AnonymousEntryShapes {
		add(AnonymousEntryAudit, shape.InputClass, shape.Outputs)
	}
	for _, outputs := range policy.MemberOutputs {
		add(MemberPolicy, 0, outputs)
	}
	for _, shape := range ringAuthorityShapes() {
		add(DelegatePolicy, shape.NInputs, shape.NOutputs)
	}
	for _, writes := range registry.ApplyWidths {
		add(ApplyRecords, writes, 0)
	}
	add(RegisterKey, 0, 0)
	add(Deposit, 0, 0)
	for _, width := range circuits.MergeWidths {
		add(AnonymousMerge, width, 0)
	}
	return keys
}

func ringAuthorityShapes() []protocol.Shape {
	return slices.DeleteFunc(slices.Clone(protocol.SupportedShapes), func(s protocol.Shape) bool {
		return !common.ProofShape{
			Circuit: common.TransferRingAuthorityCircuitType,
			Inputs:  uint32(s.NInputs),
			Outputs: uint32(s.NOutputs),
		}.Supported()
	})
}

func (k Key) circuitType() common.CircuitType {
	named := func(format string, args ...any) common.CircuitType {
		return common.CircuitType("custom-ring-" + fmt.Sprintf(format, args...))
	}
	switch k.Family {
	case PackedAudit:
		return named("audit-packed-%d", k.Outputs)
	case DeliveredAudit:
		return named("audit-delivered-%d", k.Outputs)
	case AnonymousAudit:
		return named("audit-anonymous-%d-%d", k.Inputs, k.Outputs)
	case AnonymousEntryAudit:
		return named("audit-anonymous-entry-%d-%d", k.Inputs, k.Outputs)
	case MemberPolicy:
		return named("policy-member-%d", k.Outputs)
	case DelegatePolicy:
		return named("policy-delegate-%dx%d", k.Inputs, k.Outputs)
	case ApplyRecords:
		return named("apply-records-%d", k.Inputs)
	case RegisterKey:
		return named("register-key")
	case Deposit:
		return named("deposit")
	case AnonymousMerge:
		return named("merge-anonymous-%d", k.Inputs)
	}
	panic(fmt.Sprintf("ring: unknown ring family %d", k.Family))
}
