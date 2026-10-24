package ringtest

import (
	"math/big"
	"reflect"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
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

// RequirePublicInputBound solves assignment, then requires a refusal once its PublicInputHash moves by one.
func RequirePublicInputBound(t testing.TB, circuit, assignment frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
	moved := reflect.New(reflect.TypeOf(assignment).Elem())
	moved.Elem().Set(reflect.ValueOf(assignment).Elem())
	hash := moved.Elem().FieldByName("PublicInputHash")
	hash.Set(reflect.ValueOf(frontend.Variable(new(big.Int).Add(AsBigInt(hash.Interface()), big.NewInt(1)))))
	if test.IsSolved(circuit, moved.Interface().(frontend.Circuit), ecc.BN254.ScalarField()) == nil {
		t.Fatal("solved under another public input")
	}
}
