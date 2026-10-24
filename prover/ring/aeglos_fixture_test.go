package ring

import (
	"os"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/aeglosfixture"
)

// One witness per key, decoded from its request as the server decodes it.
func TestExportAeglosRingFixtures(t *testing.T) {
	if os.Getenv("AEGLOS_FIXTURES") == "" {
		t.Skip("AEGLOS_FIXTURES is unset")
	}
	for _, key := range Keys {
		aeglosfixture.Write(t, key.KeyFile(), 0, decodeParams(t, key.Circuit, hostRequest(t, key)))
	}
}
