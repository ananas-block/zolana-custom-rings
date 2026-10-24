package circuits_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringdeposit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

func solveDeposit(c *circuits.DepositCircuit) error {
	return test.IsSolved(&circuits.DepositCircuit{}, c, ecc.BN254.ScalarField())
}

// The program builds one flag combination per ring mode, escrow only on a registry ring.
func TestDepositSolvesEveryRingMode(t *testing.T) {
	for _, tc := range []struct {
		count int
		mode  ringdeposit.RingMode
	}{{1, ringdeposit.ModeRegistry}, {circuits.MaxDeposits, ringdeposit.ModeRegistry}, {2, ringdeposit.ModeAnonymous}, {2, ringdeposit.ModeOff}} {
		if err := solveDeposit(ringdeposit.Build(t, tc.count, tc.mode).Circuit); err != nil {
			t.Fatalf("count %d mode %d: %v", tc.count, tc.mode, err)
		}
	}
}

// Each case changes one value of an honest deposit, rebinding the statement when the value is a statement element.
func TestDepositRefusals(t *testing.T) {
	define := []string{"circuits.(*DepositCircuit).Define"}
	tests := []struct {
		name   string
		mode   ringdeposit.RingMode
		tamper func(*testing.T, *ringdeposit.Deposit)
		frames []string
	}{
		{"a commitment whose blinding is not in the CRDB domain", ringdeposit.ModeRegistry, func(t *testing.T, d *ringdeposit.Deposit) {
			// The commitments and the auditor's openings all use the raw secret as the blinding.
			*d = *ringdeposit.BuildBlinded(t, 2, ringdeposit.ModeRegistry, func(_ testing.TB, secret *big.Int) *big.Int { return secret })
		}, append([]string{"[assertIsEqual]"}, define...)},
		{"an escrowed owner opened through another member's record", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.Members[0] = d.Circuit.Members[1]
		}, []string{"gadget.AssertEqualWhen", "registry.QuadRecordOpening.AssertPresent"}},
		{"a record escrowing another key", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.CtHashes[0] = big.NewInt(0xdd)
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a padding slot with a blinding secret", ringdeposit.ModeRegistry, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.BlindingSecrets[circuits.MaxDeposits-1] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"an anonymous owner hash of another key", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][1] = 0
		}, append([]string{"gadget.AssertEqualWhen"}, define...)},
		{"a key disclosed by a ring that is not anonymous", ringdeposit.ModeOff, func(_ *testing.T, d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][0] = 1
		}, append([]string{"gadget.AssertZeroWhen"}, define...)},
		{"owner key bytes outside 0..255 with the same owner identity", ringdeposit.ModeAnonymous, func(_ *testing.T, d *ringdeposit.Deposit) {
			// Moving 256 between adjacent bytes keeps the identity, the envelope's byte table refuses the encoding.
			key := &d.Circuit.OwnerKeys[0]
			key[3], key[4] = key[3].(int)-1, key[4].(int)+256
		}, append([]string{"shared.Envelope.Seal"}, define...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := ringdeposit.Build(t, 2, tt.mode)
			tt.tamper(t, d)
			ringtest.RequireRefused(t, solveDeposit(d.Circuit), tt.frames...)
		})
	}
}

func TestDepositKey(t *testing.T) {
	ringkey.RequirePinned(t, "custom_ring_deposit", ringkey.Compile(t, &circuits.DepositCircuit{}))
}
