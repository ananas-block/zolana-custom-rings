package ring

import (
	"encoding/json"
	"maps"
	"os"
	"regexp"
	"slices"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/provingkeys"
)

func TestKeysMatchTheRustCatalog(t *testing.T) {
	rust, err := os.ReadFile("../../program-libs/interface/src/ring_keys.rs")
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for _, match := range regexp.MustCompile(`name: "([a-z0-9-]+)"`).FindAllSubmatch(rust, -1) {
		want = append(want, string(match[1]))
	}
	got := make([]string, len(Keys))
	for i, key := range Keys {
		got[i] = string(key.Circuit)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("catalog differs from ring_keys.rs\n got %v\nwant %v", got, want)
	}
}

func TestEveryKeyIsRegisteredAndPinned(t *testing.T) {
	var lock struct {
		Keys map[string]json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(lockfile, &lock); err != nil {
		t.Fatal(err)
	}
	manifest, err := provingkeys.Load()
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, len(Keys))
	for i, key := range Keys {
		extension := extensionOf(t, key.Circuit)
		if extension.KeyFile != key.KeyFile() || extension.Circuit() == nil {
			t.Fatalf("%s registers key %s", key.Circuit, extension.KeyFile)
		}
		if _, ok := manifest.Keys[key.KeyFile()]; !ok {
			t.Fatalf("%s is missing from the loaded manifest", key.KeyFile())
		}
		files[i] = key.KeyFile()
	}
	slices.Sort(files)
	if pinned := slices.Sorted(maps.Keys(lock.Keys)); !slices.Equal(files, pinned) {
		t.Fatalf("proving-keys.lock differs from the catalog\n got %v\nwant %v", pinned, files)
	}
}
