package circuits_test

import (
	"fmt"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func solveMerge(t *testing.T, cs constraint.ConstraintSystem, c *circuits.AnonymousMergeCircuit) error {
	t.Helper()
	witness, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	_, err = cs.Solve(witness)
	return err
}

func mergeCircuit(t *testing.T, width int) *circuits.AnonymousMergeCircuit {
	t.Helper()
	c, err := circuits.NewAnonymousMergeCircuit(width)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Each case changes one value of an honest merge, rebinding the statement when the value is a statement element.
func TestAnonymousMergeRefusals(t *testing.T) {
	define := []string{"[assertIsEqual]", "circuits.(*AnonymousMergeCircuit).Define"}
	dummy := []string{"shared.AssertWhen", "circuits.(*AnonymousMergeCircuit).Define"}
	envelope := []string{"shared.Envelope.Seal", "circuits.(*AnonymousMergeCircuit).Define"}
	tests := []struct {
		name   string
		tamper func(*testing.T, *ringmerge.Statement)
		frames []string
	}{
		{"wrong owner", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.OwnerKey[1] = 0
		}, define},
		{"wrong nullifier secret", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.NullifierSecret = 20
		}, define},
		{"mixed assets", func(t *testing.T, s *ringmerge.Statement) {
			// SPP would commit input one under another mint, the statement names that merge.
			other := s.Mint
			other[0] ^= 1
			utxo := protocol.Utxo{
				Domain:        big.NewInt(protocol.UtxoDomain),
				Owner:         spptest.MustOwnerHash(t, s.OwnerPkHash, s.NullifierPk),
				Asset:         ringtest.AssetField(t, other),
				Amount:        s.Amounts[1],
				Blinding:      ringtest.AsBigInt(s.Circuit.Inputs[1].Blinding),
				DataHash:      big.NewInt(0),
				RingDataHash:  ringtest.AsBigInt(s.Circuit.Inputs[1].RingDataHash),
				RingProgramID: ringtest.AsBigInt(s.Circuit.RingProgramID),
			}
			hashes := slices.Clone(s.InputHashes)
			hashes[1] = spptest.MustUtxoHash(t, utxo, big.NewInt(ringmerge.InputTreeID))
			s.PrivateTxHash = s.PrivateTx(t, hashes)
			s.Circuit.PrivateTxHash = s.PrivateTxHash
			s.Rebind(t)
		}, define},
		{"another merge's private tx hash", func(t *testing.T, s *ringmerge.Statement) {
			s.PrivateTxHash = new(big.Int).Add(s.PrivateTxHash, big.NewInt(1))
			s.Circuit.PrivateTxHash = s.PrivateTxHash
			s.Rebind(t)
		}, define},
		{"another merge's output", func(t *testing.T, s *ringmerge.Statement) {
			s.OutputHash = new(big.Int).Add(s.OutputHash, big.NewInt(1))
			s.Circuit.OutputUtxoHash = s.OutputHash
			s.Rebind(t)
		}, define},
		{"another merge's first nullifier", func(t *testing.T, s *ringmerge.Statement) {
			s.FirstNf = new(big.Int).Add(s.FirstNf, big.NewInt(1))
			s.Circuit.FirstNullifier = s.FirstNf
			s.Rebind(t)
		}, define},
		{"another ring", func(t *testing.T, s *ringmerge.Statement) {
			s.Circuit.RingProgramID = 0x5a0f
			s.Rebind(t)
		}, define},
		{"tampered disclosure field", func(t *testing.T, s *ringmerge.Statement) {
			s.Fields[0] = new(big.Int).Add(s.Fields[0], big.NewInt(1))
			s.Rebind(t)
		}, define},
		{"disclosure under another key", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.DisclosureKey[0] = 0
		}, define},
		{"disclosure for another auditor", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.AuditorPk[1] = 0
		}, define},
		{"disclosure key bytes outside 0..255 packing to the same key", func(_ *testing.T, s *ringmerge.Statement) {
			// Moving 256 between adjacent bytes keeps the pad key, the envelope's byte table refuses the encoding.
			key := &s.Circuit.DisclosureKey
			key[0], key[1] = key[0].(int)-1, key[1].(int)+256
		}, envelope},
		{"dummy first input", func(_ *testing.T, s *ringmerge.Statement) {
			// A well-formed dummy in slot zero, the slot SPP seeds every derived merge value from.
			s.Circuit.Inputs[0] = circuits.MergeInput{Domain: protocol.DummyDomain, TreeID: 0, Amount: 0, Blinding: s.Circuit.Inputs[0].Blinding, RingDataHash: 0}
		}, define},
		{"hidden input amount", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[1].Amount = 8
		}, define},
		{"padding with an amount", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.Inputs[2].Amount = 1
		}, dummy},
		{"public hash of another statement", func(_ *testing.T, s *ringmerge.Statement) {
			s.Circuit.PublicInputHash = 1
		}, define},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := ringmerge.Build(t, 8)
			tt.tamper(t, s)
			ringtest.RequireRefused(t, test.IsSolved(mergeCircuit(t, 8), s.Circuit, ecc.BN254.ScalarField()), tt.frames...)
		})
	}
}

// Every SPP merge width without an anonymous key is refused at construction and at compile time.
func TestAnonymousMergeRejectsUnsupportedWidth(t *testing.T) {
	for _, width := range append(slices.DeleteFunc(slices.Clone(mergeshared.SupportedInputCounts), func(n int) bool {
		return slices.Contains(circuits.MergeWidths, n)
	}), 9) {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			if _, err := circuits.NewAnonymousMergeCircuit(width); err == nil {
				t.Fatal("built a width no anonymous merge key ships")
			}
			unchecked := &circuits.AnonymousMergeCircuit{NumInputs: width, Inputs: make([]circuits.MergeInput, width)}
			if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, unchecked); err == nil {
				t.Fatal("compiled a width no anonymous merge key ships")
			}
		})
	}
}

// Every shipped width holds its pin and solves an honest merge.
func TestAnonymousMergeCost(t *testing.T) {
	for _, width := range circuits.MergeWidths {
		t.Run(fmt.Sprint(width), func(t *testing.T) {
			cs := ringkey.Compile(t, mergeCircuit(t, width))
			ringkey.RequirePinned(t, fmt.Sprintf("custom_ring_merge_anonymous_v2_%d", width), cs)
			if err := solveMerge(t, cs, ringmerge.Build(t, width).Circuit); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAnonymousMergeParties(t *testing.T) {
	for _, width := range circuits.MergeWidths {
		for i := range 3 {
			s := ringmerge.Build(t, width)
			s.Circuit.PartyIdentities[i] = s.OwnerPkHash
			s.Rebind(t)
			if test.IsSolved(mergeCircuit(t, width), s.Circuit, ecc.BN254.ScalarField()) == nil {
				t.Fatal("owner accepted as public party")
			}
			s.Circuit.PartyIdentities[i] = 0
			s.Rebind(t)
			if err := test.IsSolved(mergeCircuit(t, width), s.Circuit, ecc.BN254.ScalarField()); err != nil {
				t.Fatal(err)
			}
			s.Circuit.PartyIdentities[i] = 99
			if test.IsSolved(mergeCircuit(t, width), s.Circuit, ecc.BN254.ScalarField()) == nil {
				t.Fatal("unbound party accepted")
			}
		}
	}
}
