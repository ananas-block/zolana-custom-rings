package ringtest

import (
	"strings"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
)

// RequireRefused fails unless err names every frame of the stack gnark's test engine records at its first failure.
func RequireRefused(t testing.TB, err error, frames ...string) {
	t.Helper()
	if err == nil {
		t.Fatal("solved")
	}
	for _, frame := range frames {
		if !strings.Contains(err.Error(), frame) {
			t.Fatalf("refused outside %s: %v", frame, err)
		}
	}
}

func RegisteredHint(t testing.TB, suffix string) solver.Hint {
	t.Helper()
	for _, hint := range solver.GetRegisteredHints() {
		if strings.HasSuffix(solver.GetHintName(hint), suffix) {
			return hint
		}
	}
	t.Fatalf("no registered hint ends in %s", suffix)
	return nil
}
