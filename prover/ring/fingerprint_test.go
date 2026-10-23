package ring

import (
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover/common"
)

// A changed constraint system breaks every proof until the keys rotate.
var expectedFingerprints = map[common.CircuitType]struct{ constraints, public int }{
	CustomRingPolicyCircuitType:           {constraints: 463087, public: 2},
	CustomRingCompressedPolicyCircuitType: {constraints: 1137117, public: 2},
	CustomRingKeyRegisterCircuitType:      {constraints: 80819, public: 2},
	CustomRingDepositCircuitType:          {constraints: 208516, public: 2},
	CustomRingDelegatePolicyCircuitType:   {constraints: 450712, public: 2},
	CustomRingBaseCircuitType:             {constraints: 124723, public: 2},
}

func TestRingCircuitFingerprintsMatchTheKeys(t *testing.T) {
	if len(RingCircuits) != len(expectedFingerprints) {
		t.Fatalf("%d ring circuits, %d fingerprints", len(RingCircuits), len(expectedFingerprints))
	}
	for _, circuit := range RingCircuits {
		t.Run(string(circuit.Type), func(t *testing.T) {
			ccs, err := circuit.R1CS()
			if err != nil {
				t.Fatal(err)
			}
			want := expectedFingerprints[circuit.Type]
			if ccs.GetNbConstraints() != want.constraints || ccs.GetNbPublicVariables() != want.public {
				t.Fatalf("%s has %d constraints and %d public variables, run just regen-custom-ring-keys before repinning",
					circuit.Type, ccs.GetNbConstraints(), ccs.GetNbPublicVariables())
			}
		})
	}
}
