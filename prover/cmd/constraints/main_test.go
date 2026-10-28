package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestCountsUseRegisteredCircuit(t *testing.T) {
	const name common.CircuitType = "custom-ring-policy-member-v2-2-w0-own"
	var key ring.Key
	for _, candidate := range ring.Keys {
		if candidate.Circuit == name {
			key = candidate
		}
	}
	var output bytes.Buffer
	if err := writeCounts(&output, []ring.Key{key}); err != nil {
		t.Fatal(err)
	}
	var got measurement
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Circuit != name || got.Constraints != ringkey.Pinned["custom_ring_policy_member_v2_2_w0_own"] {
		t.Fatalf("unexpected count report %+v", got)
	}
	if got.PublicInputs != 1 || got.Commitments != 1 || len(got.R1CSSHA256) != 64 {
		t.Fatalf("unexpected verifier shape %+v", got)
	}
}

func TestCountsRejectUnknownCircuit(t *testing.T) {
	if err := writeCounts(io.Discard, []ring.Key{{Circuit: "unknown"}}); err == nil {
		t.Fatal("unknown circuit accepted")
	}
}

func TestCountsRejectEmptySelection(t *testing.T) {
	if err := writeCounts(io.Discard, nil); err == nil {
		t.Fatal("empty selection accepted")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestCountsPropagateOutputFailure(t *testing.T) {
	key := ring.Key{Circuit: "custom-ring-policy-member-v2-2-w0-own"}
	if err := writeCounts(failingWriter{}, []ring.Key{key}); err != io.ErrClosedPipe {
		t.Fatalf("unexpected output error %v", err)
	}
}
