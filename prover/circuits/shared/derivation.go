// Holds the hashes that ring proofs, the programs and the SDKs must compute the
// same way. Each kind of hash starts with its own tag, so a value made for one
// purpose cannot pass as another.
//
// Read first. Read before shared/disclosure.go, shared/envelope.go,
// audit/audit.go.

// Package shared holds the ring derivations, the auditor envelope and the SPP openings two or more ring circuits share.
package shared

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Ring domains, distinct ASCII tags mirrored by program-libs/interface/src/proof/domain.rs and sdk-libs/ts/src/crypto/derivation/ring-domain.ts.
const (
	// AuditStatementDomain = "CRAU"
	AuditStatementDomain = 0x43524155
	// DeliveredSlotSecretDomain = "CRDS"
	DeliveredSlotSecretDomain = 0x43524453
	// BlindingSeedDomain = "CRBS"
	BlindingSeedDomain = 0x43524253
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
	// WithdrawalsDomain = "CRPW"
	WithdrawalsDomain = 0x43525057
	// TransferStatementDomain = "CRTX"
	TransferStatementDomain = 0x43525458
	// AuthorizedAddressDomain = "CRAD"
	AuthorizedAddressDomain = 0x43524144
	// RecipientTagDomain = "CRRT"
	RecipientTagDomain = 0x43525254
	// SenderTagDomain = "CRST"
	SenderTagDomain = 0x43525354
	// TrackingLeafDomain = "CRTK"
	TrackingLeafDomain = 0x4352544b
	// TrackingEntryDomain = "CRTQ"
	TrackingEntryDomain = 0x43525451
	// ApplyEnrollmentsDomain = "CRTA"
	ApplyEnrollmentsDomain = 0x43525441
	// ListSaltDomain = "CRPS"
	ListSaltDomain = 0x43525053
	// ListTagDomain = "CRPT"
	ListTagDomain = 0x43525054
)

// TransferStatementVersion is bound nonzero and last into every transfer statement, mirrored by TRANSFER_STATEMENT_VERSION in program-libs/interface/src/proof/domain.rs.
const TransferStatementVersion = 4

// PolicyStatementVersion binds the policy statement layout, mirrored by PolicyStatement::elements in program-libs/interface/src/proof/statement.rs.
const PolicyStatementVersion = 4

// Envelope and merge pad domains, mirrored by sdk-libs/client/src/crypto/encryption/mod.rs, its merge_disclosure module and sdk-libs/ts/src/crypto/audit/audit.ts.
const (
	// DomSepCRShared = "CR_S"
	DomSepCRShared = 0x43525f53
)

// Key schedule labels, distinct per ciphertext kind.
const (
	// AuditEncInfo mirrors AUDIT_STREAM_LABEL in program-libs/interface/src/proof/domain.rs.
	AuditEncInfo = "CRING/adt1"
	// BodyEncInfo mirrors DELIVERED_BODY_LABEL.
	BodyEncInfo = "CRING/bdy1"
	// NfKeyEncInfo mirrors REGISTER_KEY_LABEL.
	NfKeyEncInfo = "CRING/nfk1"
	// DepositEncInfo mirrors DEPOSIT_AUDIT_LABEL.
	DepositEncInfo = "CRING/dep1"
	// MergeEncInfo mirrors MERGE_RECORD_LABEL.
	MergeEncInfo = "CRING/mrg2"
	// RecipientBodyEncInfo mirrors RECIPIENT_BODY_LABEL.
	RecipientBodyEncInfo = "CRING/rcp1"
	// SenderBundleEncInfo mirrors SENDER_BUNDLE_LABEL.
	SenderBundleEncInfo = "CRING/snd1"
)

const (
	// BodyLen mirrors DELIVERED_BODY_LEN.
	BodyLen = 104
	// EscrowBodyLen mirrors ESCROWED_DELIVERED_BODY_LEN.
	EscrowBodyLen = 72
	// RecipientBodyLen mirrors RECIPIENT_BODY_LEN, be32(blinding) ‖ u64be(amount) ‖ mint.
	RecipientBodyLen = 72
	// SenderBundleHeadLen mirrors SENDER_BUNDLE_HEAD_LEN, mint0 ‖ u64be(amount0) ‖ u64be(amount1) ‖ output_seed.
	SenderBundleHeadLen = 80
)

// ZeroNullifierPk is Poseidon(0), mirrored by ZERO_NULLIFIER_PUBKEY in zolana/program-libs/interface/src/lib.rs, a note under it waives only the escrow requirement.
var ZeroNullifierPk, _ = new(big.Int).SetString("2a09a9fd93c590c26b91effbb2499f07e8f7aa12e2b4940a3aed2411cb65e11c", 16)

// SolAssetField is the native SOL asset, mirrored by SOL_ASSET_FIELD in zolana/program-libs/interface/src/lib.rs.
var SolAssetField, _ = new(big.Int).SetString("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864", 16)

// EscrowOwed is escrowed while the key is no ZeroNullifierPk, a program-owned note escrows nothing and still answers every other rule.
func EscrowOwed(api frontend.API, escrowed, nullifierPk frontend.Variable) frontend.Variable {
	return api.Mul(escrowed, api.Sub(1, api.IsZero(api.Sub(nullifierPk, ZeroNullifierPk))))
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

// BlindingSeed is SPP's blinding_seed Poseidon(CRBS, sk0, sk1, salt), every output blinding rebuilds from tx_viewing_sk.
func BlindingSeed(api frontend.API, txViewingSk [2]frontend.Variable, salt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{BlindingSeedDomain, txViewingSk[0], txViewingSk[1], salt})
}

// DepositBlinding is Poseidon(CRDB, blindingSecret), domain separated from every SPP output blinding.
func DepositBlinding(api frontend.API, blindingSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{DepositBlindingDomain, blindingSecret})
}

// ListSalt is Poseidon(CRPS, nullifierSecret), one way, a holder learns the owner's private list position and never the secret.
func ListSalt(api frontend.API, nullifierSecret frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ListSaltDomain, nullifierSecret})
}

// ListTag is Poseidon(CRPT, listSalt), the tracking leaf's commitment to the owner's one salt.
func ListTag(api frontend.API, listSalt frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{ListTagDomain, listSalt})
}

// AnonymousParties counts payer, five co-signers and exit destination, mirrored by ANONYMOUS_PARTIES.
const AnonymousParties = 7

// AssertAnonymousParties separates the hidden owner from the public identities
// reconstructed by the verifier. Zero denotes an absent optional party.
func AssertAnonymousParties(api frontend.API, owner frontend.Variable, parties []frontend.Variable) {
	for _, party := range parties {
		abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: party, V: api.IsZero(api.Sub(owner, party))})
	}
}
