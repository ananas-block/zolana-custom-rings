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
	Reserved     bool
	FullOpenings bool
}

func (l Layout) Value() int64 {
	return ringtest.Bit(l.Escrow)*audit.LayoutEscrow |
		ringtest.Bit(l.Reserved)*audit.LayoutReserved | ringtest.Bit(l.FullOpenings)*audit.LayoutFullOpenings
}

// StatementOutput is one published output as an audit statement reads it.
type StatementOutput struct {
	Hash       *big.Int
	Exit       bool
	U          [32]byte
	Ciphertext []byte
}

type AnonymousTail struct {
	InputCount      int
	PrivateTxHash   *big.Int
	PartyIdentities [3]*big.Int
}

func DeliveredStatement(t testing.TB, head AuditHead, outputs []StatementOutput) []*big.Int {
	t.Helper()
	return append(head.Elements(t),
		OutputChain(t, outputs), OutputCiphertextChain(t, outputs), RecipientKeyChain(t, outputs), ExitsBitmap(outputs))
}

func RecipientKeyChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	var keys []*big.Int
	for _, output := range outputs {
		lo, hi := ringprotocol.Pack32(output.U)
		if output.Exit {
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
		OutputChain(t, outputs), OutputCiphertextChain(t, outputs), big.NewInt(int64(tail.InputCount)), ExitsBitmap(outputs), tail.PrivateTxHash,
		tail.PartyIdentities[0], tail.PartyIdentities[1], tail.PartyIdentities[2])
}

func OutputChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = output.Hash
	}
	return spptest.MustHashChain4(t, hashes)
}

func OutputCiphertextChain(t testing.TB, outputs []StatementOutput) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(outputs))
	for i, output := range outputs {
		hashes[i] = ringtest.HashBytes(t, output.Ciphertext)
	}
	return spptest.MustHashChain4(t, hashes)
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
