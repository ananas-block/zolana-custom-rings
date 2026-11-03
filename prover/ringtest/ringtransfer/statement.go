package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

// Statement is what the program holds for a transfer statement, the family picks the elements.
type Statement struct {
	Head                                        ringaudit.AuditHead
	InProof, Delegate, Exempt, ApprovalRequired bool
	Outputs                                     []ringaudit.StatementOutput
	InputCount                                  int
	PrivateTxHash                               *big.Int
	// Sender is the confidential family's statement sender, PartyIdentities the anonymous family's parties.
	Sender          *big.Int
	PartyIdentities [3]*big.Int
	SignerCount     int
	SignerChain     *big.Int
	// Anonymous family only.
	BundleDigest, BundleTag, ReplyDigest  *big.Int
	PolicyHash, OwnRoot, CuratorRoot      *big.Int
	Recipients                            []*big.Int
	PublicAssets, PublicNets, PublicGross [3]*big.Int
	WithdrawalHash                        *big.Int
}

// ConfidentialElements mirrors TransferStatement::elements under TransferFamily::Confidential.
func (s Statement) ConfidentialElements(t testing.TB) []*big.Int {
	t.Helper()
	elements := append(s.Head.ElementsUnder(t, shared.TransferStatementDomain),
		bitField(s.InProof), bitField(s.Delegate), bitField(s.Exempt), bitField(s.ApprovalRequired),
		big.NewInt(int64(ringaudit.OutputCount(s.Outputs))),
		ringaudit.OutputChain(t, s.Outputs), ringaudit.OutputCiphertextChain(t, s.Outputs), ringaudit.RecipientKeyChain(t, s.Outputs),
		big.NewInt(int64(s.InputCount)), ringaudit.ExitsBitmap(s.Outputs), s.PrivateTxHash,
		s.Sender,
		big.NewInt(int64(s.SignerCount)), s.SignerChain,
		s.PolicyHash, s.OwnRoot, s.CuratorRoot,
	)
	elements = append(elements, s.Recipients...)
	return s.tail(s.withPublic(elements))
}

// AnonymousElements mirrors TransferStatement::elements under TransferFamily::Anonymous.
func (s Statement) AnonymousElements(t testing.TB) []*big.Int {
	t.Helper()
	elements := append(s.Head.ElementsUnder(t, shared.TransferStatementDomain),
		bitField(s.Exempt), bitField(s.ApprovalRequired),
		big.NewInt(int64(ringaudit.OutputCount(s.Outputs))),
		ringaudit.OutputChain(t, s.Outputs), ringaudit.OutputCiphertextChain(t, s.Outputs), ringaudit.RecipientBodyChain(t, s.Outputs), ringaudit.RecipientTagChain(t, s.Outputs, s.BundleTag),
		ringaudit.ChangeBitmap(s.Outputs), s.BundleDigest,
		big.NewInt(int64(s.InputCount)), ringaudit.ExitsBitmap(s.Outputs), s.PrivateTxHash,
		s.PartyIdentities[0], s.PartyIdentities[1], s.PartyIdentities[2],
		big.NewInt(int64(s.SignerCount)), s.SignerChain,
		s.PolicyHash, s.OwnRoot, s.CuratorRoot,
	)
	return s.tail(append(s.withPublic(elements), s.ReplyDigest))
}

func (s Statement) withPublic(elements []*big.Int) []*big.Int {
	for k := range s.PublicAssets {
		elements = append(elements, s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k])
	}
	return append(elements, s.WithdrawalHash)
}

func (s Statement) tail(elements []*big.Int) []*big.Int {
	return append(elements, big.NewInt(int64(len(elements)+2)), big.NewInt(shared.TransferStatementVersion))
}

func bitField(set bool) *big.Int {
	if set {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}
