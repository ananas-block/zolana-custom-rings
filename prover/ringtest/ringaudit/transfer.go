package ringaudit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Transfer is the part of a ring transfer every audit statement opens with.
type Transfer struct {
	Keys           Keys
	FirstNullifier *big.Int
	RingProgramID  *big.Int
	Salt           [16]byte
	SeedOut        *big.Int
}

// NewTransfer is the fixture transfer of the default keys in the ring of program address 0x90..90.
func NewTransfer(t testing.TB) Transfer {
	t.Helper()
	ringProgram := ringtest.Repeat(0x90)
	tr := Transfer{
		FirstNullifier: big.NewInt(0x1f1f),
		RingProgramID:  ringtest.HashBytes(t, ringProgram[:]),
	}
	for i := range tr.Salt {
		tr.Salt[i] = 0xa0 + byte(i)
	}
	return tr.WithKeys(t, DefaultKeys(t))
}

// WithKeys rederives SeedOut, the CRBS blinding seed follows tx_viewing_sk.
func (tr Transfer) WithKeys(t testing.TB, keys Keys) Transfer {
	t.Helper()
	tr.Keys = keys
	seedOut, err := protocol.OutputBlindingSeed(tr.FirstNullifier, ringprotocol.BlindingSeed(t, tr.Keys.txViewingSk, tr.Salt))
	tr.SeedOut = spptest.MustHash(t, seedOut, err)
	return tr
}

// Blinding is the TXOB blinding SPP derives for slot i of the transfer.
func (tr Transfer) Blinding(t testing.TB, i int) *big.Int {
	t.Helper()
	return ringprotocol.OutputBlinding(t, tr.FirstNullifier, tr.SeedOut, i)
}

func (tr Transfer) AuditHead(t testing.TB, layout Layout, envelope []byte) AuditHead {
	t.Helper()
	head := tr.Keys.AuditHead(t, tr.FirstNullifier, tr.RingProgramID, tr.Salt, envelope)
	head.Layout = layout.Value()
	return head
}

// Wires are the audit wires of the transfer under layout.
func (tr Transfer) Wires(layout Layout) audit.AuditWires {
	w := audit.AuditWires{FirstNullifier: tr.FirstNullifier, RingProgramID: tr.RingProgramID, Layout: layout.Value()}
	ringtest.SetBytes(w.TxViewingSk[:], tr.Keys.txViewingSk[:])
	ringtest.SetBytes(w.EphSk[:], tr.Keys.ephSk[:])
	ringtest.SetBytes(w.AuditorPk[:], tr.Keys.auditorPk[:])
	ringtest.SetBytes(w.Salt[:], tr.Salt[:])
	return w
}

// OutputTreeID is the fixture tree every output is appended to.
const OutputTreeID = 9

// inputTreeID is the fixture tree every input spends from.
const inputTreeID = 3

// SpentUtxo is a data-free input of owner in the given ring, 0 for the default ring.
func SpentUtxo(t testing.TB, ownerPkHash, nullifierPk, ringID *big.Int, amount uint64, blinding int64) Utxo {
	t.Helper()
	return Utxo{
		Domain: protocol.UtxoDomain, TreeID: inputTreeID, OwnerPkHash: ownerPkHash, NullifierPk: nullifierPk,
		Asset: ringtest.AssetField(t, FixtureMint), Amount: amount, Blinding: big.NewInt(blinding),
		DataHash: big.NewInt(0), RingDataHash: big.NewInt(0), RingProgramID: ringID,
	}
}

// SpareInput is a slot past the published count.
func SpareInput(i int) Utxo {
	return Dummy(inputTreeID, big.NewInt(0x9000+int64(i)))
}

// SpentHashes is the private_tx_hash entry of every slot, zero off a UTXO.
func SpentHashes(t testing.TB, utxos []Utxo) []*big.Int {
	t.Helper()
	hashes := make([]*big.Int, len(utxos))
	for i, utxo := range utxos {
		hashes[i] = utxo.spentHash(t)
	}
	return hashes
}

// FixtureMint is the mint of every fixture note.
var FixtureMint = ringtest.Repeat(0x0a)
