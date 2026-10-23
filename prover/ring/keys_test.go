package ring

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/consensys/gnark/constraint"

	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestRingKeysCarryTheCompiledCircuits(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		compile func() (constraint.ConstraintSystem, error)
	}{
		{name: string(CustomRingPolicyCircuitType), file: CustomRingPolicyKeyFile, compile: R1CSPolicy},
		{name: string(CustomRingBaseCircuitType), file: CustomRingBaseKeyFile, compile: R1CSBase},
		{name: string(CustomRingDelegatePolicyCircuitType), file: CustomRingDelegatePolicyKeyFile, compile: R1CSDelegatePolicy},
		{name: string(CustomRingCompressedPolicyCircuitType), file: CustomRingCompressedPolicyKeyFile, compile: R1CSCompressedPolicy},
		{name: string(CustomRingKeyRegisterCircuitType), file: CustomRingKeyRegisterKeyFile, compile: R1CSKeyRegister},
		{name: string(CustomRingDepositCircuitType), file: CustomRingDepositKeyFile, compile: R1CSDeposit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded := loadRingSystem(t, test.file)
			compiled, err := test.compile()
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			var fromKey, fresh bytes.Buffer
			if _, err := loaded.ConstraintSystem.WriteTo(&fromKey); err != nil {
				t.Fatalf("write key circuit: %v", err)
			}
			if _, err := compiled.WriteTo(&fresh); err != nil {
				t.Fatalf("write compiled circuit: %v", err)
			}
			if !bytes.Equal(fromKey.Bytes(), fresh.Bytes()) {
				t.Fatalf("%s does not carry the compiled circuit, %d against %d constraints, rotate the keys",
					test.file, loaded.ConstraintSystem.GetNbConstraints(), compiled.GetNbConstraints())
			}
		})
	}
}

func decodeRequest(circuit common.ExtensionCircuit, payload []byte) (common.ExtensionRequest, error) {
	request := circuit.Request()
	return request, json.Unmarshal(payload, request)
}

// Skips the test when the workspace key cache has no <file>.
func loadRingSystem(t *testing.T, file string) *common.ExtensionProofSystem {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "zolana", "prover", "server", "proving-keys", file)
	if _, err := os.Stat(path); err != nil {
		t.Skipf("%s is not available", file)
	}
	loaded, err := common.ReadSystemFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	system, ok := loaded.(*common.ExtensionProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	return system
}

// A proof's path names its key file, the provers must name exactly the pinned keys.
func TestKeyFilesAreTheLockfileKeys(t *testing.T) {
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	pinned := slices.Sorted(maps.Keys(manifest.Keys))
	if got := common.KeyFiles(); !slices.Equal(got, pinned) {
		t.Fatalf("key files %v, lockfiles %v", got, pinned)
	}
}
