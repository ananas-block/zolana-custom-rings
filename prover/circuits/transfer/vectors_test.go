package transfer_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type statementOutputVector struct {
	Kind          string `json:"kind"`
	Hash          string `json:"hash"`
	U             string `json:"u,omitempty"`
	Body          string `json:"body,omitempty"`
	Record        string `json:"record,omitempty"`
	RecipientBody string `json:"recipient_body,omitempty"`
	Tag           string `json:"tag,omitempty"`
}

type withdrawalVector struct {
	Owner  string `json:"owner"`
	Asset  string `json:"asset"`
	Amount uint64 `json:"amount"`
}

// transferStatementVector reads proof/ring-statements.json from Rust and writes audit/transfer_statement_v3.json from Go, one preimage per chain and digest position.
type transferStatementVector struct {
	Name             string                  `json:"name,omitempty"`
	Family           string                  `json:"family"`
	Rail             string                  `json:"rail,omitempty"`
	InProof          bool                    `json:"in_proof"`
	Delegate         bool                    `json:"delegate"`
	Exempt           bool                    `json:"exempt"`
	ApprovalRequired bool                    `json:"approval_required"`
	FirstNullifier   string                  `json:"first_nullifier"`
	RingProgramID    string                  `json:"ring_id"`
	TxViewingU       string                  `json:"tx_viewing_u"`
	AuditorPubkey    string                  `json:"auditor_pubkey"`
	EphU             string                  `json:"eph_u"`
	Envelope         string                  `json:"envelope"`
	Salt             string                  `json:"salt"`
	Layout           int64                   `json:"layout"`
	OutputCapacity   int                     `json:"output_capacity"`
	OutputCount      int                     `json:"output_count,omitempty"`
	Outputs          []statementOutputVector `json:"outputs"`
	InputCount       int                     `json:"input_count"`
	ChangeBitmap     *uint64                 `json:"change_bitmap,omitempty"`
	SenderBundle     string                  `json:"sender_bundle,omitempty"`
	SenderBundleTag  string                  `json:"sender_bundle_tag,omitempty"`
	Replies          string                  `json:"replies,omitempty"`
	PrivateTxHash    string                  `json:"private_tx_hash"`
	Sender           string                  `json:"sender,omitempty"`
	PartyIdentities  []string                `json:"party_identities,omitempty"`
	SignerSlots      int                     `json:"signer_slots,omitempty"`
	Signers          []string                `json:"signers,omitempty"`
	SignerCount      int                     `json:"signer_count"`
	SignerChain      string                  `json:"signer_chain"`
	PolicyHash       string                  `json:"policy_hash"`
	OwnRoot          string                  `json:"own_root"`
	CuratorRoot      string                  `json:"curator_root"`
	Recipients       []string                `json:"recipients,omitempty"`
	PublicAssets     [3]string               `json:"public_assets"`
	PublicAmounts    [3]string               `json:"public_amounts"`
	PublicGross      [3]string               `json:"public_gross"`
	Withdrawals      []withdrawalVector      `json:"withdrawals,omitempty"`
	WithdrawalHash   string                  `json:"withdrawal_hash"`
	Elements         []string                `json:"elements"`
	PublicInputHash  string                  `json:"public_input_hash"`
}

// statement rebuilds the host statement from the vector's preimages alone.
func (v transferStatementVector) statement(t *testing.T) ringtransfer.Statement {
	t.Helper()
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
		SignerCount:    v.SignerCount,
		SignerChain:    ringtest.VectorField(t, v.SignerChain),
		PolicyHash:     ringtest.VectorField(t, v.PolicyHash),
		OwnRoot:        ringtest.VectorField(t, v.OwnRoot),
		CuratorRoot:    ringtest.VectorField(t, v.CuratorRoot),
		WithdrawalHash: ringtest.VectorField(t, v.WithdrawalHash),
	}
	for i, o := range v.Outputs {
		output := ringaudit.StatementOutput{Hash: ringtest.VectorField(t, o.Hash), Exit: o.Kind == "exit"}
		if o.U != "" {
			output.U = [32]byte(ringtest.VectorBytes(t, o.U, 32))
		}
		ciphertext := o.Body + o.Record
		output.Ciphertext = ringtest.VectorBytes(t, ciphertext, len(ciphertext)/2)
		if o.RecipientBody != "" {
			output.Body = ringtest.VectorBytes(t, o.RecipientBody, len(o.RecipientBody)/2)
		}
		if o.Tag != "" {
			output.Tag = ringtest.VectorField(t, o.Tag)
		}
		output.Change = v.ChangeBitmap != nil && *v.ChangeBitmap>>i&1 == 1
		s.Outputs = append(s.Outputs, output)
	}
	for len(s.Outputs) < v.OutputCapacity {
		s.Outputs = append(s.Outputs, ringaudit.StatementOutput{Hash: big.NewInt(0), Omitted: true})
	}
	for k := range s.PublicAssets {
		s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k] = ringtest.VectorField(t, v.PublicAssets[k]), ringtest.VectorField(t, v.PublicAmounts[k]), ringtest.VectorField(t, v.PublicGross[k])
	}
	switch v.Family {
	case "confidential":
		s.Sender = ringtest.VectorField(t, v.Sender)
		for _, recipient := range v.Recipients {
			s.Recipients = append(s.Recipients, ringtest.VectorField(t, recipient))
		}
		// An omitted slot's recipient cell reads zero.
		for len(s.Recipients) < v.OutputCapacity {
			s.Recipients = append(s.Recipients, big.NewInt(0))
		}
	case "anonymous":
		for i, party := range v.PartyIdentities {
			s.PartyIdentities[i] = ringtest.VectorField(t, party)
		}
		s.BundleDigest = ringprotocol.EnvelopeDigest(t, ringtest.VectorBytes(t, v.SenderBundle, len(v.SenderBundle)/2))
		s.BundleTag = ringtest.VectorField(t, v.SenderBundleTag)
		s.ReplyDigest = big.NewInt(0)
		if v.Replies != "" {
			s.ReplyDigest = ringprotocol.EnvelopeDigest(t, ringtest.VectorBytes(t, v.Replies, len(v.Replies)/2))
		}
	default:
		t.Fatalf("unknown transfer family %q", v.Family)
	}
	return s
}

func (v transferStatementVector) elements(t *testing.T) []*big.Int {
	t.Helper()
	if v.Family == "confidential" {
		return v.statement(t).ConfidentialElements(t)
	}
	return v.statement(t).AnonymousElements(t)
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
			rails[v.Rail] = true
			requireElements(t, v.elements(t), v.Elements, v.PublicInputHash)
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
