// Package ringprotocol is the host twin of circuits/shared for the Go tests.
package ringprotocol

import (
	"crypto/ecdh"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// DeliveredSlotSecret mirrors shared.DeliveredSlot.Secret over X25519(tx_viewing_sk, u).
func DeliveredSlotSecret(t testing.TB, txViewingSk [32]byte, u [32]byte, salt [16]byte, i int, firstNullifier *big.Int) *big.Int {
	t.Helper()
	peer, err := ecdh.X25519().NewPublicKey(u[:])
	if err != nil {
		t.Fatal(err)
	}
	tx := XPrivateKey(t, txViewingSk)
	agreement, err := tx.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	dhLo, dhHi := Pack32([32]byte(agreement))
	txLo, txHi := Pack33(Tagged(tx.PublicKey().Bytes()))
	rLo, rHi := Pack33(Tagged(u[:]))
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.DeliveredSlotSecretDomain), dhLo, dhHi, txLo, txHi, rLo, rHi,
		new(big.Int).SetBytes(salt[:]), big.NewInt(int64(i)), firstNullifier)
}

// BlindingSeed mirrors shared.BlindingSeed.
func BlindingSeed(t testing.TB, txViewingSk [32]byte, salt [16]byte) *big.Int {
	t.Helper()
	keyLo, keyHi := Pack32(txViewingSk)
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.BlindingSeedDomain), keyLo, keyHi, new(big.Int).SetBytes(salt[:]))
}

// AnonymousRingData mirrors shared.AnonymousRingData.
func AnonymousRingData(t testing.TB, slotSecret, tag *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.AnonymousRingDataDomain), slotSecret, tag)
}

// OutputBlinding is SPP's TXOB blinding of slot i under the output blinding seed.
func OutputBlinding(t testing.TB, firstNullifier, seedOut *big.Int, i int) *big.Int {
	t.Helper()
	blinding, err := protocol.OutputBlinding(firstNullifier, seedOut, i)
	return spptest.MustHash(t, blinding, err)
}

// DepositBlinding mirrors shared.DepositBlinding.
func DepositBlinding(t testing.TB, blindingSecret *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.DepositBlindingDomain), blindingSecret)
}

// InboxKey mirrors shared.InboxKey over pack_be(0x04 ‖ u).
func InboxKey(t testing.TB, ringID *big.Int, u [32]byte) *big.Int {
	t.Helper()
	rLo, rHi := Pack33(Tagged(u[:]))
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.InboxKeyDomain), ringID, rLo, rHi)
}

// InboxTagDigest mirrors shared.InboxTagDigest.
func InboxTagDigest(t testing.TB, inboxKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.InboxTagDomain), inboxKey, new(big.Int).SetUint64(epoch), new(big.Int).SetUint64(index))
}

// InboxTag is the low TagLen bytes of the inbox tag digest.
func InboxTag(t testing.TB, inboxKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return LowTag(InboxTagDigest(t, inboxKey, epoch, index))
}

// PairKey mirrors shared.PairKey.
func PairKey(t testing.TB, firstContact *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.PairKeyDomain), firstContact)
}

// PairTag is the low TagLen bytes of shared.PairTagDigest.
func PairTag(t testing.TB, pairKey *big.Int, epoch, index uint64) *big.Int {
	t.Helper()
	return LowTag(ringtest.MustPoseidonHash(t, big.NewInt(shared.PairTagDomain), pairKey, new(big.Int).SetUint64(epoch), new(big.Int).SetUint64(index)))
}

// LowTag mirrors shared.TagField, the low TagLen bytes of a canonical field value.
func LowTag(value *big.Int) *big.Int {
	return new(big.Int).And(value, new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 8*shared.TagLen), big.NewInt(1)))
}

// SenderCommitment mirrors shared.SenderCommitment.
func SenderCommitment(t testing.TB, senderPkHash, privateTxBlinding *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.SenderCommitmentDomain), senderPkHash, privateTxBlinding)
}
