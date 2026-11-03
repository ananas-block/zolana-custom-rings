package ring

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
)

// Frame byte lengths the circuit does not bind itself, mirrored by program-libs/interface/src/instructions/transact.rs.
const (
	frameProofLen    = 192
	frameSppProofLen = 128
	frameTreeLen     = 4
	frameExitBodyLen = 83
)

type frameRail int

const (
	frameConfidential frameRail = iota
	frameDelegate
	frameCommitment
	frameEntry
)

// frameCases lists the rail of every line of settlement/frame_v3.hex, in Fixture::cases order.
var frameCases = []frameRail{frameConfidential, frameConfidential, frameConfidential, frameConfidential, frameCommitment, frameEntry, frameDelegate, frameCommitment, frameCommitment, frameConfidential}

type frameCursor struct {
	t    *testing.T
	rest []byte
}

func (c *frameCursor) take(n int) []byte {
	c.t.Helper()
	if n > len(c.rest) {
		c.t.Fatalf("frame ends %d bytes short", n-len(c.rest))
	}
	head := c.rest[:n]
	c.rest = c.rest[n:]
	return head
}

func (c *frameCursor) bits(count int) uint64 {
	c.t.Helper()
	bits := uint64(0)
	for i, b := range c.take((count + 7) / 8) {
		bits |= uint64(b) << (8 * i)
	}
	return bits
}

// The Go lengths walk every frame the program parses to its last byte, a length off the program's would miss the end.
func TestFrameVectorWalksEveryField(t *testing.T) {
	lines := vectorLines(t, "../../test-vectors/settlement/frame_v3.hex")
	if len(lines) != len(frameCases) {
		t.Fatalf("%d frames, %d cases", len(lines), len(frameCases))
	}
	for i, line := range lines {
		t.Run(fmt.Sprint(i), func(t *testing.T) { walkTransferFrame(t, line, frameCases[i]) })
	}
}

func walkTransferFrame(t *testing.T, line []byte, rail frameRail) {
	t.Helper()
	const (
		policyFlag, curatorFlag, ownerInProof, exemptFlag, secondTree, replyFlag = 1, 2, 8, 16, 32, 64
		defaultOwnerTag, keyEscrow, lowBits                                      = 64, 64, 63
	)
	anonymous := rail == frameCommitment || rail == frameEntry
	c := frameCursor{t: t, rest: line}
	head := c.take(4)
	flags, shape, inputByte, m := head[0], head[1], head[2], int(head[3])
	n := int(inputByte & lowBits)
	if m < 1 || m > 16 {
		t.Fatalf("output count %d", m)
	}
	c.take(frameProofLen)
	if flags&(policyFlag|exemptFlag) != 0 || anonymous {
		c.take(8)
	}
	if flags&curatorFlag != 0 {
		c.take(8)
	}
	if flags&policyFlag != 0 && !anonymous {
		c.take(32 * m)
	}
	c.take(4 + 32 + 16)
	transfers := int(c.take(1)[0])
	splWithdrawals := 0
	for range transfers {
		kind := c.take(1)[0]
		c.take(8)
		if kind >= 2 {
			c.take(1)
		}
		if kind == 3 {
			splWithdrawals++
		}
	}
	if flags&policyFlag != 0 {
		c.take(32 * splWithdrawals)
	}
	exits := c.bits(m)
	changes := uint64(0)
	if anonymous {
		changes = c.bits(m)
	}
	escrow := inputByte&keyEscrow != 0
	bodies := 0
	for slot := range m {
		switch {
		case exits>>slot&1 == 1:
			c.take(32 + 32 + frameExitBodyLen)
		case changes>>slot&1 == 1:
			c.take(32 + 32)
		case anonymous:
			c.take(32 + 32 + shared.RecipientBodyLen)
			bodies++
		case escrow:
			c.take(32 + 32 + shared.EscrowBodyLen)
		default:
			c.take(32 + 32 + shared.BodyLen)
		}
	}
	if flags&replyFlag != 0 {
		c.take(int(binary.LittleEndian.Uint16(c.take(2))) * bodies)
	}
	if anonymous {
		c.take(32 + shared.SenderBundleHeadLen + 32*m)
	}
	c.take(32)
	ranges := audit.ConfidentialRanges(n, m)
	if rail == frameEntry {
		ranges = audit.EntryRanges(n, m)
	}
	c.take(ranges.EnvelopeLen(n))
	for slot := range m {
		switch {
		case exits>>slot&1 == 1 && escrow:
			c.take(audit.EscrowExitRecordLen)
		case exits>>slot&1 == 1:
			c.take(audit.ExitRecordLen)
		case anonymous:
			c.take(audit.AnonymousRecordLen)
		}
	}
	c.take(32)
	if anonymous {
		c.take(64)
		if shape&defaultOwnerTag != 0 {
			c.take(32)
		}
	}
	if flags&ownerInProof != 0 {
		c.take(96)
	}
	c.take(frameSppProofLen + 32*n)
	if flags&secondTree != 0 {
		c.bits(n)
		c.take(frameTreeLen)
	}
	c.take(frameTreeLen)
	if len(c.rest) != 0 {
		t.Fatalf("%d bytes past the last field", len(c.rest))
	}
}

func TestMergeFrameVectorWalksTheDisclosure(t *testing.T) {
	lines := vectorLines(t, "../../test-vectors/merge/merge_frame_v2.hex")
	c := frameCursor{t: t, rest: lines[0]}
	c.take(8 + 32 + frameProofLen + 33 + 32)
	fields := int(c.take(1)[0])
	if fields != (32*circuits.MergeWidths[0]+30)/31 {
		t.Fatalf("%d disclosure fields", fields)
	}
	c.take(32 * fields)
	if len(c.rest) == 0 {
		t.Fatal("the frame holds no SPP merge body")
	}
}

func vectorLines(t *testing.T, path string) [][]byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		decoded, err := hex.DecodeString(line)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, decoded)
	}
	return lines
}
