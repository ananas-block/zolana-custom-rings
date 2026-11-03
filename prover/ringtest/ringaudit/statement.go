package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// AuditHead is what the program holds for the head of an audit statement, mirrors AuditHead in program-libs/interface/src/proof/statement.rs.
type AuditHead struct {
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	TxViewingU     [32]byte
	AuditorPubkey  [33]byte
	EphU           [32]byte
	// Envelope is the transmitted envelope ciphertext, its digest head element 9.
	Envelope []byte
	Salt     [16]byte
	Layout   int64
}

func (h AuditHead) Elements(t testing.TB) []*big.Int {
	t.Helper()
	txLo, txHi := ringprotocol.Pack33(ringprotocol.Tagged(h.TxViewingU[:]))
	auditorLo, auditorHi := ringprotocol.Pack33(h.AuditorPubkey)
	ephLo, ephHi := ringprotocol.Pack33(ringprotocol.Tagged(h.EphU[:]))
	return []*big.Int{
		big.NewInt(shared.AuditStatementDomain), h.FirstNullifier, h.RingProgramID, txLo, txHi,
		auditorLo, auditorHi, ephLo, ephHi, ringprotocol.EnvelopeDigest(t, h.Envelope), new(big.Int).SetBytes(h.Salt[:]), big.NewInt(h.Layout),
	}
}

// ElementsUnder is the head under domain, the transfer statement's CRTX in place of CRAU.
func (h AuditHead) ElementsUnder(t testing.TB, domain int64) []*big.Int {
	t.Helper()
	elements := h.Elements(t)
	elements[0] = big.NewInt(domain)
	return elements
}

// Layout is a transfer's layout flags, mirrors the Layout flags of package audit.
type Layout struct {
	Escrow       bool
	FullOpenings bool
}

func (l Layout) Value() int64 {
	return ringtest.Bit(l.Escrow)*audit.LayoutEscrow | ringtest.Bit(l.FullOpenings)*audit.LayoutFullOpenings
}

// StatementOutput is one output slot as an audit statement reads it, an omitted one reads zero.
type StatementOutput struct {
	Hash       *big.Int
	Exit       bool
	U          [32]byte
	Ciphertext []byte
	// Body is the scheme 11 ciphertext, nil on change, an exit and an omitted slot.
	Body    []byte
	Change  bool
	Omitted bool
	// Tag is the discovery tag, nil on change, an exit and an omitted slot.
	Tag *big.Int
}

type AnonymousTail struct {
	OutputCount     int
	BundleDigest    *big.Int
	BundleTag       *big.Int
	InputCount      int
	PrivateTxHash   *big.Int
	PartyIdentities [3]*big.Int
	SignerCount     int
	SignerChain     *big.Int
}

// SignerChain mirrors transfer.OpenSigners over a run of the key's slots, zero at a count of zero.
func SignerChain(t testing.TB, signers []*big.Int, slots int) *big.Int {
	t.Helper()
	if len(signers) == 0 {
		return big.NewInt(0)
	}
	cells := make([]*big.Int, slots)
	for i := range cells {
		cells[i] = big.NewInt(0)
	}
	copy(cells, signers)
	return spptest.MustHashChain4(t, cells)
}

func DeliveredStatement(t testing.TB, head AuditHead, outputs []StatementOutput) []*big.Int {
	t.Helper()
	return append(head.Elements(t),
		big.NewInt(int64(OutputCount(outputs))), OutputChain(t, outputs), OutputCiphertextChain(t, outputs), RecipientKeyChain(t, outputs), ExitsBitmap(outputs))
}

func OutputCount(outputs []StatementOutput) int {
	count := 0
	for _, output := range outputs {
		if !output.Omitted {
			count++
		}
	}
	return count
}

func RecipientKeyChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	var keys []*big.Int
	for _, output := range outputs {
		lo, hi := ringprotocol.Pack32(output.U)
		if output.Exit || output.Omitted {
			lo, hi = big.NewInt(0), big.NewInt(0)
		}
		keys = append(keys, lo, hi)
	}
	return spptest.MustHashChain4(t, keys)
}

func DeliveredSenderStatement(t testing.TB, head AuditHead, outputs []StatementOutput, inputCount int, privateTxHash, sender *big.Int) []*big.Int {
	t.Helper()
	return append(DeliveredStatement(t, head, outputs), big.NewInt(int64(inputCount)), privateTxHash, sender)
}

func AnonymousStatement(t testing.TB, head AuditHead, outputs []StatementOutput, tail AnonymousTail) []*big.Int {
	t.Helper()
	return append(head.Elements(t),
		big.NewInt(int64(tail.OutputCount)), OutputChain(t, outputs), OutputCiphertextChain(t, outputs), RecipientBodyChain(t, outputs), RecipientTagChain(t, outputs, tail.BundleTag),
		ChangeBitmap(outputs), tail.BundleDigest,
		big.NewInt(int64(tail.InputCount)), ExitsBitmap(outputs), tail.PrivateTxHash,
		tail.PartyIdentities[0], tail.PartyIdentities[1], tail.PartyIdentities[2],
		big.NewInt(int64(tail.SignerCount)), tail.SignerChain)
}

func OutputChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = output.Hash
		if output.Omitted {
			hashes[i] = big.NewInt(0)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}

func OutputCiphertextChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = big.NewInt(0)
		if !output.Omitted {
			hashes[i] = ringtest.HashBytes(t, output.Ciphertext)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}

// RecipientBodyChain mirrors recipient_body_chain, zero on change, an exit and an omitted slot.
func RecipientBodyChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = big.NewInt(0)
		if output.Body != nil {
			hashes[i] = ringtest.HashBytes(t, output.Body)
		}
	}
	return spptest.MustHashChain4(t, hashes)
}

// RecipientTagChain mirrors recipient_tag_chain, zero on change, an exit and an omitted slot, the bundle's tag last.
func RecipientTagChain(t testing.TB, outputs []StatementOutput, bundleTag *big.Int) *big.Int {
	t.Helper()
	cells := make([]*big.Int, 0, len(outputs)+1)
	for _, output := range outputs {
		cell := big.NewInt(0)
		if output.Tag != nil {
			cell = output.Tag
		}
		cells = append(cells, cell)
	}
	return spptest.MustHashChain4(t, append(cells, bundleTag))
}

func ExitsBitmap(outputs []StatementOutput) *big.Int {
	bitmap := new(big.Int)
	for i, output := range outputs {
		if output.Exit {
			bitmap.SetBit(bitmap, i, 1)
		}
	}
	return bitmap
}

func ChangeBitmap(outputs []StatementOutput) *big.Int {
	bitmap := new(big.Int)
	for i, output := range outputs {
		if output.Change {
			bitmap.SetBit(bitmap, i, 1)
		}
	}
	return bitmap
}
