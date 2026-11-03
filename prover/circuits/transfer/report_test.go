package transfer_test

import (
	"bytes"
	"encoding/json"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
)

// RING_PROVE_REPORT=<path> sets up and proves every transfer key once and appends one JSON line per key, the catalog's cost measurement.
func TestTransferKeysProveReport(t *testing.T) {
	path := os.Getenv("RING_PROVE_REPORT")
	if path == "" {
		t.Skip("RING_PROVE_REPORT is unset")
	}
	out, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	report := func(name string, circuit, assignment frontend.Circuit) {
		t.Run(name, func(t *testing.T) {
			cs := ringkey.Compile(t, circuit)
			start := time.Now()
			pk, vk, err := groth16.Setup(cs)
			if err != nil {
				t.Fatal(err)
			}
			setup := time.Since(start)
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			var memory runtime.MemStats
			start = time.Now()
			proof, err := groth16.Prove(cs, pk, witness)
			if err != nil {
				t.Fatal(err)
			}
			prove := time.Since(start)
			runtime.ReadMemStats(&memory)
			public, err := witness.Public()
			if err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(proof, vk, public); err != nil {
				t.Fatal(err)
			}
			var key bytes.Buffer
			if _, err := pk.WriteTo(&key); err != nil {
				t.Fatal(err)
			}
			line, err := json.Marshal(map[string]any{
				"key": name, "constraints": cs.GetNbConstraints(), "setup_ms": setup.Milliseconds(), "prove_ms": prove.Milliseconds(),
				"proving_key_bytes": key.Len(), "heap_sys_bytes": memory.HeapSys, "threads": runtime.GOMAXPROCS(0),
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := out.Write(append(line, '\n')); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, shape := range transfer.ConfidentialShapes {
		circuit, err := transfer.NewConfidentialTransferCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		report(shape.String(), circuit, ringtransfer.Signed(shape).Build(t).Circuit)
	}
	for _, shape := range append(transfer.AnonymousShapes[:], transfer.EntryShapes[:]...) {
		circuit, err := transfer.NewAnonymousTransferCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		report(shape.String(), circuit, ringtransfer.Hidden(shape).Build(t).Circuit)
	}
}
