package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type transferStatementVector struct {
	Family           string `json:"family"`
	Rail             string `json:"rail"`
	InProof          bool   `json:"in_proof"`
	Delegate         bool   `json:"delegate"`
	Exempt           bool   `json:"exempt"`
	ApprovalRequired bool   `json:"approval_required"`
	FirstNullifier   string `json:"first_nullifier"`
	RingProgramID    string `json:"ring_id"`
	TxViewingU       string `json:"tx_viewing_u"`
	AuditorPubkey    string `json:"auditor_pubkey"`
	EphU             string `json:"eph_u"`
	Envelope         string `json:"envelope"`
	Salt             string `json:"salt"`
	Layout           int64  `json:"layout"`
	Outputs          []struct {
		Kind   string `json:"kind"`
		Hash   string `json:"hash"`
		U      string `json:"u"`
		Body   string `json:"body"`
		Record string `json:"record"`
	} `json:"outputs"`
	InputCount      int       `json:"input_count"`
	PrivateTxHash   string    `json:"private_tx_hash"`
	Sender          string    `json:"sender"`
	PartyIdentities []string  `json:"party_identities"`
	PolicyHash      string    `json:"policy_hash"`
	OwnRoot         string    `json:"own_root"`
	CuratorRoot     string    `json:"curator_root"`
	Recipients      []string  `json:"recipients"`
	PublicAssets    [3]string `json:"public_assets"`
	PublicAmounts   [3]string `json:"public_amounts"`
	PublicGross     [3]string `json:"public_gross"`
	WithdrawalHash  string    `json:"withdrawal_hash"`
	Elements        []string  `json:"elements"`
	PublicInputHash string    `json:"public_input_hash"`
}

// The host builder every honest witness solves against rebuilds the program's transfer statements of the Rust vector, element by element.
func TestTransferStatementsMatchRustVectors(t *testing.T) {
	var vectors struct {
		Transfer []transferStatementVector `json:"transfer"`
	}
	ringtest.ReadVector(t, "proof/ring-statements.json", &vectors)
	rails := map[string]bool{}
	for _, v := range vectors.Transfer {
		t.Run(v.Family+" "+v.Rail, func(t *testing.T) {
			s := ringtransfer.Statement{
				Head: ringaudit.AuditHead{
					FirstNullifier: ringtest.VectorField(t, v.FirstNullifier),
					RingProgramID:  ringtest.VectorField(t, v.RingProgramID),
					TxViewingU:     [32]byte(ringtest.VectorBytes(t, v.TxViewingU, 32)),
					AuditorPubkey:  [33]byte(ringtest.VectorBytes(t, v.AuditorPubkey, 33)),
					EphU:           [32]byte(ringtest.VectorBytes(t, v.EphU, 32)),
					Envelope:       ringtest.VectorBytes(t, v.Envelope, len(v.Envelope)/2),
					Salt:           [16]byte(ringtest.VectorBytes(t, v.Salt, 16)),
					Layout:         v.Layout,
				},
				InProof: v.InProof, Delegate: v.Delegate, Exempt: v.Exempt, ApprovalRequired: v.ApprovalRequired,
				InputCount:     v.InputCount,
				PrivateTxHash:  ringtest.VectorField(t, v.PrivateTxHash),
				PolicyHash:     ringtest.VectorField(t, v.PolicyHash),
				OwnRoot:        ringtest.VectorField(t, v.OwnRoot),
				CuratorRoot:    ringtest.VectorField(t, v.CuratorRoot),
				WithdrawalHash: ringtest.VectorField(t, v.WithdrawalHash),
			}
			for _, o := range v.Outputs {
				output := ringaudit.StatementOutput{Hash: ringtest.VectorField(t, o.Hash), Exit: o.Kind == "exit"}
				if o.U != "" {
					output.U = [32]byte(ringtest.VectorBytes(t, o.U, 32))
				}
				ciphertext := o.Body + o.Record
				output.Ciphertext = ringtest.VectorBytes(t, ciphertext, len(ciphertext)/2)
				s.Outputs = append(s.Outputs, output)
			}
			for k := range s.PublicAssets {
				s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k] = ringtest.VectorField(t, v.PublicAssets[k]), ringtest.VectorField(t, v.PublicAmounts[k]), ringtest.VectorField(t, v.PublicGross[k])
			}
			var elements []*big.Int
			switch v.Family {
			case "confidential":
				s.Sender = ringtest.VectorField(t, v.Sender)
				for _, recipient := range v.Recipients {
					s.Recipients = append(s.Recipients, ringtest.VectorField(t, recipient))
				}
				elements = s.ConfidentialElements(t)
			case "anonymous":
				for i, party := range v.PartyIdentities {
					s.PartyIdentities[i] = ringtest.VectorField(t, party)
				}
				elements = s.AnonymousElements(t)
			default:
				t.Fatalf("unknown transfer family %q", v.Family)
			}
			rails[v.Rail] = true
			requireElements(t, elements, v.Elements, v.PublicInputHash)
		})
	}
	for _, rail := range []string{"signer", "in_proof", "delegate", "anonymous", "entry"} {
		if !rails[rail] {
			t.Errorf("the vector has no %s case", rail)
		}
	}
}

func requireElements(t *testing.T, elements []*big.Int, want []string, publicInputHash string) {
	t.Helper()
	if len(elements) != len(want) {
		t.Fatalf("%d elements, the vector holds %d", len(elements), len(want))
	}
	for i, element := range elements {
		if element.Cmp(ringtest.VectorField(t, want[i])) != 0 {
			t.Errorf("element %d is %x, the vector holds %s", i, element, want[i])
		}
	}
	if hash := spptest.MustHashChain4(t, elements); hash.Cmp(ringtest.VectorField(t, publicInputHash)) != 0 {
		t.Errorf("public input %x, the vector holds %s", hash, publicInputHash)
	}
}
