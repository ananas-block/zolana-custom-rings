// Package shared holds the ring derivations, the auditor envelope and the SPP openings two or more ring circuits share.
package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Ring domains, distinct ASCII tags mirrored by program-libs/interface/src/domain.rs and sdk-libs/ts/src/keypair/ring-domain.ts.
const (
	// AuditStatementDomain = "CRAU"
	AuditStatementDomain = 0x43524155
	// PackedSlotSecretDomain = "CRAS"
	PackedSlotSecretDomain = 0x43524153
	// DeliveredSlotSecretDomain = "CRDS"
	DeliveredSlotSecretDomain = 0x43524453
	// ConfidentialRingSecretDomain = "CRRC"
	ConfidentialRingSecretDomain = 0x43525243
	// AnonymousRingSecretDomain = "CRRA"
	AnonymousRingSecretDomain = 0x43525241
	// InboxKeyDomain = "CRIK"
	InboxKeyDomain = 0x4352494b
	// InboxTagDomain = "CRIT"
	InboxTagDomain = 0x43524954
	// PairKeyDomain = "CRPK"
	PairKeyDomain = 0x4352504b
	// PairTagDomain = "CRPT"
	PairTagDomain = 0x43525054
	// SenderCommitmentDomain = "CRSC"
	SenderCommitmentDomain = 0x43525343
	// DisclosurePadDomain = "CROD"
	DisclosurePadDomain = 0x43524f44
	// PolicyStatementDomain = "CRPO"
	PolicyStatementDomain = 0x4352504f
	// PolicyTableDomain = "CRTB"
	PolicyTableDomain = 0x43525442
	// QueueWriteDomain = "CRQW"
	QueueWriteDomain = 0x43525157
	// ApplyRecordsDomain = "CRAP"
	ApplyRecordsDomain = 0x43524150
	// RegisterKeyDomain = "CRRG"
	RegisterKeyDomain = 0x43525247
	// DepositStatementDomain = "CRDP"
	DepositStatementDomain = 0x43524450
	// MergeStatementDomain = "CRMG"
	MergeStatementDomain = 0x43524d47
	// DepositBlindingDomain = "CRDB"
	DepositBlindingDomain = 0x43524442
)

// RingOutputBlindingDomainV1 = "TXRB".
const RingOutputBlindingDomainV1 = 0x54585242

// Envelope and merge pad domains, mirrored by sdk-libs/client/src/encryption.rs, its merge_disclosure module and sdk-libs/ts/src/keypair/audit.ts.
const (
	// DomSepCRShared = "CR_S"
	DomSepCRShared = 0x43525f53
	// MergeDisclosureDomain = "CR_MD", a merge pad under the same key never repeats an output pad.
	MergeDisclosureDomain = 0x4352_5f4d44
)

// Key schedule labels, distinct per ciphertext kind.
const (
	// AuditEncInfo is the audit stream schedule tag, mirrored by AUDIT_STREAM_INFO in program-libs/interface/src/anonymous_output.rs.
	AuditEncInfo = "CRING/adt1"
	// NfKeyEncInfo separates the key ciphertext from the audit one, mirrored by NF_KEY_ENC_INFO in sdk-libs/client/src/encryption.rs.
	NfKeyEncInfo   = "CRING/nfk1"
	DepositEncInfo = "CRING/dep1"
	MergeEncInfo   = "CRING/mrg1"
)

// Tag stream bounds, mirrored by program-libs/interface/src/stream.rs and sdk-libs/ts/src/keypair/ring-stream.ts.
const (
	// EpochSlots is the tag epoch length, the program sets epoch = slot / EpochSlots.
	EpochSlots = 1 << 18
	// StreamIndexBits bounds inbox and pair indexes alike, one range check serves every slot.
	StreamIndexBits = 6
	JInbox          = 1 << StreamIndexBits
	JPair           = 1 << StreamIndexBits
	// PairEpochBits bounds the epochs a pair stream lives after its anchor.
	PairEpochBits = 5
	KPairEpochs   = 1 << PairEpochBits
	// TagLen is the low128 width, the owner tag is 0^16 ‖ tag.
	TagLen = 16
)

// BodyLen is asset_address(32) ‖ u64be(amount).
const BodyLen = 40

// PackedSlot is a packed rail slot secret preimage, TxViewingSk = pack_be(tx_viewing_sk).
type PackedSlot struct {
	TxViewingSk    [2]frontend.Variable
	Salt           frontend.Variable
	OutputIndex    frontend.Variable
	FirstNullifier frontend.Variable
}

// Secret is Poseidon(CRAS, key0, key1, salt, i, n0), held only by the sender and the auditor of tx_viewing_sk.
func (s PackedSlot) Secret(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		PackedSlotSecretDomain, s.TxViewingSk[0], s.TxViewingSk[1], s.Salt, s.OutputIndex, s.FirstNullifier,
	})
}

// DeliveredSlot is a delivered slot secret preimage, Agreement = pack_be(X25519(tx_viewing_sk, u)) and each key pack_be(0x04 ‖ u).
type DeliveredSlot struct {
	Agreement      [2]frontend.Variable
	TxPk           [2]frontend.Variable
	Recipient      [2]frontend.Variable
	Salt           frontend.Variable
	OutputIndex    frontend.Variable
	FirstNullifier frontend.Variable
}

// Secret is Poseidon(CRDS, dh0, dh1, txpk0, txpk1, r0, r1, salt, i, n0), the recipient rebuilds it from X25519(u_sk, tx_u).
func (s DeliveredSlot) Secret(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		DeliveredSlotSecretDomain, s.Agreement[0], s.Agreement[1], s.TxPk[0], s.TxPk[1],
		s.Recipient[0], s.Recipient[1], s.Salt, s.OutputIndex, s.FirstNullifier,
	})
}

// InboxKey is Poseidon(CRIK, ringID, r0, r1), recipient = pack_be(0x04 ‖ u) of the address viewing key.
func InboxKey(api frontend.API, ringID frontend.Variable, recipient [2]frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{InboxKeyDomain, ringID, recipient[0], recipient[1]})
}

// InboxTagDigest is Poseidon(CRIT, inboxKey, epoch, index), the caller bounds index below JInbox.
func InboxTagDigest(api frontend.API, inboxKey, epoch, index frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{InboxTagDomain, inboxKey, epoch, index})
}

// PairKey is Poseidon(CRPK, firstContact), firstContact the delivered slot secret of the anchor.
func PairKey(api frontend.API, firstContact frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{PairKeyDomain, firstContact})
}

// PairTagDigest is Poseidon(CRPT, pairKey, epoch, index), the caller bounds index below JPair.
func PairTagDigest(api frontend.API, pairKey, epoch, index frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{PairTagDomain, pairKey, epoch, index})
}

// TagField is low128(value), one tag per field since SplitField refuses the split of value + q.
func TagField(api frontend.API, rc frontend.Rangechecker, value frontend.Variable) frontend.Variable {
	_, low := ringgadget.SplitField(api, rc, value, 8*TagLen)
	return low
}

// ConfidentialRingSecret is Poseidon(CRRC, slotSecret), a ring secret no anchor accepts.
func ConfidentialRingSecret(api frontend.API, slotSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ConfidentialRingSecretDomain, slotSecret})
}

// AnonymousRingSecret is Poseidon(CRRA, slotSecret, tag), binding the published tag into the output blinding.
func AnonymousRingSecret(api frontend.API, slotSecret, tag frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{AnonymousRingSecretDomain, slotSecret, tag})
}

// SenderCommitment binds the anonymous audit and the member policy to one sender, private_tx_hash fixes the blinding both read.
func SenderCommitment(api frontend.API, senderPkHash, privateTxBlinding frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SenderCommitmentDomain, senderPkHash, privateTxBlinding})
}

// DepositBlinding is Poseidon(CRDB, blindingSecret), a deposit blinding no anchor opens as a first contact.
func DepositBlinding(api frontend.API, blindingSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{DepositBlindingDomain, blindingSecret})
}

// DeriveRingOutputBlinding is bound by the ring's audit proof, never by SPP.
func DeriveRingOutputBlinding(api frontend.API, firstNullifier, ringSecret, outputIndex frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{RingOutputBlindingDomainV1, firstNullifier, ringSecret, outputIndex})
}

// DeriveRingRailOutputBlinding is TXOB over seed when inDefaultRing is 1 and TXRB over ringSecret when it is 0.
func DeriveRingRailOutputBlinding(api frontend.API, inDefaultRing, firstNullifier, seed, ringSecret frontend.Variable, outputIndex int) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		api.Select(inDefaultRing, transaction.OutputBlindingDomainV1, RingOutputBlindingDomainV1),
		firstNullifier,
		api.Select(inDefaultRing, seed, ringSecret),
		outputIndex,
	})
}
