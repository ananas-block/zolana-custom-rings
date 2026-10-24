package ring

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const goldenDigests = "testdata/witness.sha256"

// rustGolden is written by the Rust SDK, in its own key order.
const rustGolden = "../../sdk-libs/sdk/tests/fixtures/custom-ring-audit-anonymous-exit.json"

// UPDATE_RING_GOLDENS=1 rewrites the digests, never the fixtures.
func TestGoldenRequestsAssignTheRecordedWitness(t *testing.T) {
	files := append(goldenFiles(t), rustGolden)
	digests := map[string]string{}
	for _, file := range files {
		name := filepath.Base(file)
		payload, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		meta, err := common.ParseProofRequestMeta(payload)
		if err != nil {
			t.Fatal(err)
		}
		witness, solved := solvedWitness(t, meta.CircuitType, payload)
		if solved != nil {
			t.Errorf("%s does not solve: %v", name, solved)
		}
		encoded, err := witness.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		digests[name] = hex.EncodeToString(digest[:])
	}
	if os.Getenv("UPDATE_RING_GOLDENS") != "" {
		writeDigests(t, digests)
		return
	}
	want := readDigests(t)
	if len(want) != len(digests) {
		t.Fatalf("%d fixtures against %d digests", len(digests), len(want))
	}
	for name, digest := range digests {
		if want[name] != digest {
			t.Errorf("%s assigns a different witness", name)
		}
	}
}

func goldenFiles(t testing.TB) []string {
	t.Helper()
	files, err := filepath.Glob("testdata/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	return files
}

func readDigests(t *testing.T) map[string]string {
	t.Helper()
	file, err := os.Open(goldenDigests)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digests := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		digest, name, ok := strings.Cut(scanner.Text(), "  ")
		if !ok {
			t.Fatalf("malformed digest line %q", scanner.Text())
		}
		digests[name] = digest
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return digests
}

func writeDigests(t *testing.T, digests map[string]string) {
	t.Helper()
	names := make([]string, 0, len(digests))
	for name := range digests {
		names = append(names, name)
	}
	sort.Strings(names)
	var out strings.Builder
	for _, name := range names {
		fmt.Fprintf(&out, "%s  %s\n", digests[name], name)
	}
	if err := os.WriteFile(goldenDigests, []byte(out.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
