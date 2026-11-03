package policy

import (
	"testing"

	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

func TestPooledPolicyRejectsMalformedShape(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Policy)
	}{
		{"missing outputs", func(p *Policy) {
			p.CtHashes = nil
			p.OwnerEntries = nil
			p.AssetEntries = nil
			p.OwnRecords = p.OwnRecords[:1]
			p.OwnSubjects = p.OwnSubjects[:1]
			p.CuratorRecords = p.CuratorRecords[:1]
			p.CuratorSubjects = p.CuratorSubjects[:1]
		}},
		{"missing owner references", func(p *Policy) { p.OwnerEntries = nil }},
		{"missing asset references", func(p *Policy) { p.AssetEntries = nil }},
		{"missing own records", func(p *Policy) { p.OwnRecords = nil }},
		{"missing own subjects", func(p *Policy) { p.OwnSubjects = nil }},
		{"missing sender references", func(p *Policy) { p.SenderEntries = nil }},
		{"missing curator reference", func(p *Policy) { p.SenderEntries[0].Curator = nil }},
		{"oversized own pool", func(p *Policy) { p.OwnRecords = append(p.OwnRecords, p.OwnRecords[0]) }},
		{"missing public asset references", func(p *Policy) { p.PublicAssetEntries = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPolicy(InputsShape{Outputs: 2, Senders: 4}.Inputs(), RecordPoolShape{}, transaction.NPublicSlots)
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(&p)
			if err = p.Validate(transaction.NPublicSlots); err == nil {
				t.Fatal("invalid policy shape accepted")
			}
		})
	}
	t.Run("own registry with curator records", func(t *testing.T) {
		p, err := NewPolicy(InputsShape{Outputs: 2, Senders: 4, OwnOnly: true}.Inputs(), RecordPoolShape{}, transaction.NPublicSlots)
		if err != nil {
			t.Fatal(err)
		}
		p.CuratorRecords = p.OwnRecords[:1]
		if err = p.Validate(transaction.NPublicSlots); err == nil {
			t.Fatal("curator records accepted by own only shape")
		}
	})
}
