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
	HasData bool
	Entry   bool
}

func (l Layout) Value() int64 {
	return ringtest.Bit(l.HasData)*audit.LayoutHasData | ringtest.Bit(l.Entry)*audit.LayoutEntry
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

// RegionChain mirrors record_chain and tail_chain, zero past the published regions.
func RegionChain(t testing.TB, regions [][]byte, capacity int) *big.Int {
	t.Helper()
	hashes := make([]*big.Int, capacity)
	for i := range hashes {
		hashes[i] = big.NewInt(0)
		if i < len(regions) {
			hashes[i] = ringtest.HashBytes(t, regions[i])
		}
	}
	return spptest.MustHashChain4(t, hashes)
}

// OutputChain mirrors output_chain over the published hashes, zero past them.
func OutputChain(t testing.TB, hashes []*big.Int, capacity int) *big.Int {
	t.Helper()
	cells := make([]*big.Int, capacity)
	for i := range cells {
		cells[i] = big.NewInt(0)
		if i < len(hashes) {
			cells[i] = hashes[i]
		}
	}
	return spptest.MustHashChain4(t, cells)
}
