// Package ring registers the custom ring circuits with the SPP prover server.
package ring

import (
	_ "embed"
	"fmt"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

//go:embed proving-keys.lock
var lockfile []byte

func init() {
	for _, key := range Keys {
		common.RegisterExtension(key.extension())
	}
	provingkeys.Register(lockfile)
}

func (k Key) extension() common.ExtensionCircuit {
	switch k.Family {
	case PackedAudit:
		return bind[PackedAuditParams](k, audit.NewPackedAuditCircuit, k.Outputs)
	case DeliveredAudit:
		return bind[DeliveredAuditParams](k, audit.NewDeliveredAuditCircuit, k.Outputs)
	case AnonymousAudit, AnonymousEntryAudit:
		return bind[AnonymousAuditParams](k, audit.NewAnonymousAuditCircuit, k.anonymousShape())
	case MemberPolicy:
		return bind[MemberPolicyParams](k, policy.NewMemberPolicyCircuitWith, policy.MemberShape{Outputs: k.Outputs, Withdrawals: k.Withdrawals, OwnOnly: k.OwnOnly})
	case DelegatePolicy:
		return bind[DelegatePolicyParams](k, policy.NewDelegatePolicyCircuitWith, policy.DelegateShape{Shape: transaction.Shape{NInputs: k.Inputs, NOutputs: k.Outputs}, OwnOnly: k.OwnOnly})
	case ApplyRecords:
		return bind[ApplyRecordsParams](k, registry.NewApplyRecordsCircuit, k.Inputs)
	case RegisterKey:
		return bind[RegisterKeyParams](k, unsized[registry.RegisterKeyCircuit], struct{}{})
	case Deposit:
		return bind[DepositParams](k, circuits.NewDepositCircuit, k.Inputs)
	case AnonymousMerge:
		return bind[AnonymousMergeParams](k, circuits.NewAnonymousMergeCircuit, k.Inputs)
	}
	panic(fmt.Sprintf("ring: no circuit for ring family %d", k.Family))
}

func bind[P headed, S any, C frontend.Circuit](k Key, constructor func(S) (C, error), shape S) common.ExtensionCircuit {
	build := func() (frontend.Circuit, error) { return constructor(shape) }
	return common.ExtensionCircuit{
		Type:    k.Circuit,
		KeyFile: k.KeyFile(),
		Circuit: func() frontend.Circuit {
			circuit, err := build()
			if err != nil {
				// Every catalog shape comes from its constructor's own list.
				panic(err)
			}
			return circuit
		},
		Request: func() common.ExtensionRequest { return &request[P]{circuit: k.Circuit, build: build} },
	}
}

func unsized[C any](struct{}) (*C, error) {
	return new(C), nil
}

// request decodes strictly on the server's encoding/json path.
type request[P headed] struct {
	circuit common.CircuitType
	build   func() (frontend.Circuit, error)
	params  P
}

func (r *request[P]) UnmarshalJSON(data []byte) error {
	if err := Unmarshal(data, &r.params); err != nil {
		return err
	}
	if got := r.params.head().CircuitType; got != r.circuit {
		return fmt.Errorf("custom-ring: a %s request on the %s key", got, r.circuit)
	}
	return nil
}

// Assignment fails for a request that leaves a circuit value unset or sizes a slice off the key's shape.
func (r *request[P]) Assignment() (frontend.Circuit, error) {
	assignment, err := r.build()
	if err != nil {
		return nil, err
	}
	return assignment, assign(assignment, &r.params)
}
