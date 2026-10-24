// Package shared holds the ring derivations, the auditor envelope and the SPP openings two or more ring circuits share.
package shared

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ring domains, distinct ASCII tags mirrored by program-libs/interface/src/domain.rs and sdk-libs/ts/src/keypair/ring-domain.ts.
const (
	// AuditStatementDomain = "CRAU"
	AuditStatementDomain = 0x43524155
	// DeliveredSlotSecretDomain = "CRDS"
	DeliveredSlotSecretDomain = 0x43524453
	// BlindingSeedDomain = "CRBS"
	BlindingSeedDomain = 0x43524253
	// AnonymousRingDataDomain = "CRAT"
	AnonymousRingDataDomain = 0x43524154
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
	// EpochSlots is the tag epoch length, the program takes slot / EpochSlots or the epoch before it.
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

// BodyLen is be32(blinding) ‖ u64be(amount).
const BodyLen = 40

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

// BlindingSeed is SPP's blinding_seed Poseidon(CRBS, sk0, sk1, salt), every output blinding rebuilds from tx_viewing_sk.
func BlindingSeed(api frontend.API, txViewingSk [2]frontend.Variable, salt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{BlindingSeedDomain, txViewingSk[0], txViewingSk[1], salt})
}

// AnonymousRingData is Poseidon(CRAT, slotSecret, tag), the ring_data_hash an anchor reads a first contact's tag back from.
func AnonymousRingData(api frontend.API, slotSecret, tag frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{AnonymousRingDataDomain, slotSecret, tag})
}

// SenderCommitment binds the anonymous audit and the member policy to one sender, private_tx_hash fixes the blinding both read.
func SenderCommitment(api frontend.API, senderPkHash, privateTxBlinding frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{SenderCommitmentDomain, senderPkHash, privateTxBlinding})
}

// DepositBlinding is Poseidon(CRDB, blindingSecret), a deposit blinding no anchor opens as a first contact.
func DepositBlinding(api frontend.API, blindingSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{DepositBlindingDomain, blindingSecret})
}
