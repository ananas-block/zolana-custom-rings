package audit_test

import (
	"slices"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

type rangesVector struct {
	Family              string `json:"family"`
	Rail                string `json:"rail"`
	KeyEscrow           bool   `json:"key_escrow"`
	Class               int    `json:"class"`
	Outputs             int    `json:"outputs"`
	MaxEvidenceBlocks   int    `json:"max_evidence_blocks"`
	RecordBlocks        int    `json:"record_blocks"`
	FirstRecordCounter  int    `json:"first_record_counter"`
	CapacityBlocks      int    `json:"capacity_blocks"`
	RingCiphertextLen   int    `json:"ring_slot_ciphertext_len"`
	RingRecordLen       int    `json:"ring_slot_record_len"`
	ExitRecordLen       int    `json:"exit_record_len"`
	RecordStartCounters []int  `json:"record_start_counters"`
	EnvelopeLens        []int  `json:"envelope_len_by_input_count"`
}

func (v rangesVector) keyRanges(t *testing.T) (audit.StreamRanges, bool) {
	t.Helper()
	switch v.Rail {
	case "signer":
		return audit.ConfidentialRanges(v.Class, v.Outputs), false
	case "in_proof_or_authority":
		return audit.ConfidentialRanges(v.Class, v.Outputs), true
	case "commitment":
		return audit.CommitmentRanges(v.Class, v.Outputs), true
	case "entry":
		return audit.EntryRanges(v.Class, v.Outputs), true
	}
	t.Fatalf("unknown rail %q", v.Rail)
	return audit.StreamRanges{}, false
}

func TestStreamRangesAreTheSharedVector(t *testing.T) {
	var vectors struct {
		Keys []rangesVector `json:"keys"`
	}
	ringtest.ReadVector(t, "audit/ring-disclosure-ranges.json", &vectors)
	covered := map[string]bool{}
	for _, v := range vectors.Keys {
		t.Run(v.Rail, func(t *testing.T) {
			r, evidence := v.keyRanges(t)
			if r.MaxEvidenceBlocks() != v.MaxEvidenceBlocks || r.RecordBlocks != v.RecordBlocks || r.RecordCounter(0) != v.FirstRecordCounter || r.CapacityBlocks() != v.CapacityBlocks {
				t.Errorf("E_max %d R %d R0 %d capacity %d, the vector holds %d %d %d %d", r.MaxEvidenceBlocks(), r.RecordBlocks, r.RecordCounter(0), r.CapacityBlocks(), v.MaxEvidenceBlocks, v.RecordBlocks, v.FirstRecordCounter, v.CapacityBlocks)
			}
			counters := make([]int, v.Outputs)
			for i := range counters {
				counters[i] = r.RecordCounter(i)
			}
			if !slices.Equal(counters, v.RecordStartCounters) {
				t.Errorf("record counters %v, the vector holds %v", counters, v.RecordStartCounters)
			}
			lengths := make([]int, v.Class)
			for n := range lengths {
				count := 0
				if evidence {
					count = n + 1
				}
				lengths[n] = r.EnvelopeLen(count)
			}
			if !slices.Equal(lengths, v.EnvelopeLens) {
				t.Errorf("envelope lengths %v, the vector holds %v", lengths, v.EnvelopeLens)
			}
			ciphertext, record, exit := shared.BodyLen, 0, audit.ExitRecordLen
			if v.KeyEscrow {
				ciphertext, exit = shared.EscrowBodyLen, audit.EscrowExitRecordLen
			}
			if v.Family == "anonymous" {
				ciphertext, record = audit.AnonymousRecordLen, audit.AnonymousRecordLen
			}
			if ciphertext != v.RingCiphertextLen || record != v.RingRecordLen || exit != v.ExitRecordLen {
				t.Errorf("ring ciphertext %d record %d exit %d, the vector holds %d %d %d", ciphertext, record, exit, v.RingCiphertextLen, v.RingRecordLen, v.ExitRecordLen)
			}
		})
		covered[keyName(v.Rail == "entry", v.Family, v.Class, v.Outputs)] = true
	}
	for _, shape := range transfer.ConfidentialShapes {
		if !covered[keyName(false, "confidential", shape.Inputs, shape.Outputs)] {
			t.Errorf("the vector has no %v", shape)
		}
	}
	for _, shape := range append(transfer.AnonymousShapes[:], transfer.EntryShapes[:]...) {
		if !covered[keyName(shape.FullOpenings, "anonymous", shape.InputClass, shape.Outputs)] {
			t.Errorf("the vector has no %v", shape)
		}
	}
}

func keyName(entry bool, family string, class, outputs int) string {
	if entry {
		family = "entry"
	}
	return family + string(rune(class)) + string(rune(outputs))
}

// A record region holds its longest plaintext and no two regions share a counter.
func TestStreamRegionsHoldTheirPlaintext(t *testing.T) {
	const blockLen = 16
	if audit.AnonymousRecordBlocks*blockLen < audit.AnonymousRecordLen || audit.ConfidentialRecordBlocks*blockLen < audit.ExitRecordLen {
		t.Fatal("a record overruns its region")
	}
	for _, r := range []audit.StreamRanges{audit.ConfidentialRanges(32, 2), audit.CommitmentRanges(24, 2), audit.EntryRanges(8, 2)} {
		if r.EnvelopeLen(r.InputClass) > r.EnvelopeBlocks()*blockLen {
			t.Fatalf("%+v: the envelope overruns its region", r)
		}
		if r.RecordCounter(0) != audit.StreamFirstCounter+r.EnvelopeBlocks() || r.RecordCounter(1)-r.RecordCounter(0) != r.RecordBlocks {
			t.Fatalf("%+v: regions overlap", r)
		}
	}
}
