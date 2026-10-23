package ringtest_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/base"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
)

func TestPackedAuditAndMemberPolicyProve(t *testing.T) {
	audit, err := base.NewPackedAuditCircuit(2)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, audit, ringaudit.PackedAuditOf(t, 2, 2).Circuit(t))
	member, err := policy.NewMemberPolicyCircuit(2)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, member, ringpolicy.Confidential().Build(t).Assignment())
}

func TestAnonymousAuditTransferProves(t *testing.T) {
	shape := base.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	audit, err := base.NewAnonymousAuditCircuit(shape)
	if err != nil {
		t.Fatal(err)
	}
	requireProves(t, audit, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
}

func requireProves(t *testing.T, circuit, assignment frontend.Circuit) {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	proof, err := groth16.Prove(cs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatalf("honest proof refused: %v", err)
	}
	inputs := public.Vector().(fr.Vector)
	one := fr.One()
	inputs[0].Add(&inputs[0], &one)
	if groth16.Verify(proof, vk, public) == nil {
		t.Fatal("proof verified under another public input")
	}
}
