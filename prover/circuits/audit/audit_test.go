package audit_test

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

var compiledAudits = map[string]*ringkey.Bound{}

// compileAudit compiles circuit once per name and locates the public input binding with the honest assignment.
func compileAudit(t *testing.T, name string, circuit, honest frontend.Circuit) *ringkey.Bound {
	t.Helper()
	if c, ok := compiledAudits[name]; ok {
		return c
	}
	c := ringkey.Bind(t, circuit, honest)
	compiledAudits[name] = c
	return c
}

func compileDelivered(t *testing.T, capacity int) *ringkey.Bound {
	t.Helper()
	return compileAudit(t, deliveredKeyName(capacity), ringaudit.NewDeliveredCircuit(0, capacity), ringaudit.NewDeliveredAudit(t, capacity).Circuit(t))
}

func compileDeliveredSender(t *testing.T, shape ringaudit.SenderShape) *ringkey.Bound {
	t.Helper()
	return compileAudit(t, deliveredSenderKeyName(shape), ringaudit.NewDeliveredSenderCircuit(shape), ringaudit.NewDeliveredSenderAudit(t, shape).Circuit(t))
}

func compileAnonymous(t *testing.T, shape audit.AnonymousAuditShape) *ringkey.Bound {
	t.Helper()
	return compileAudit(t, anonymousKeyName(shape), ringaudit.NewAnonymousCircuit(shape), ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
}

func deliveredKeyName(capacity int) string {
	return fmt.Sprintf("audit_delivered_%d", capacity)
}

func deliveredSenderKeyName(shape ringaudit.SenderShape) string {
	return fmt.Sprintf("audit_delivered_sender_%d_%d", shape.Inputs, shape.Outputs)
}

func anonymousKeyName(shape audit.AnonymousAuditShape) string {
	if shape.FullOpenings {
		return fmt.Sprintf("audit_anonymous_entry_%d_%d", shape.InputClass, shape.Outputs)
	}
	return fmt.Sprintf("audit_anonymous_%d_%d", shape.InputClass, shape.Outputs)
}
