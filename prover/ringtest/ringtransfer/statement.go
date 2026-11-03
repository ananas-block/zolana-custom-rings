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
	Sender                                *big.Int
	PartyIdentities                       [3]*big.Int
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
		ringaudit.OutputChain(t, s.Outputs), ringaudit.OutputCiphertextChain(t, s.Outputs), ringaudit.RecipientKeyChain(t, s.Outputs),
		big.NewInt(int64(s.InputCount)), ringaudit.ExitsBitmap(s.Outputs),
		s.PrivateTxHash, s.Sender, s.PolicyHash, s.OwnRoot, s.CuratorRoot,
	)
	elements = append(elements, s.Recipients...)
	return s.tail(elements)
}

// AnonymousElements mirrors TransferStatement::elements under TransferFamily::Anonymous.
func (s Statement) AnonymousElements(t testing.TB) []*big.Int {
	t.Helper()
	elements := append(s.Head.ElementsUnder(t, shared.TransferStatementDomain),
		bitField(s.Exempt), bitField(s.ApprovalRequired),
		ringaudit.OutputChain(t, s.Outputs), ringaudit.OutputCiphertextChain(t, s.Outputs),
		big.NewInt(int64(s.InputCount)), ringaudit.ExitsBitmap(s.Outputs), s.PrivateTxHash,
		s.PartyIdentities[0], s.PartyIdentities[1], s.PartyIdentities[2],
		s.PolicyHash, s.OwnRoot, s.CuratorRoot,
	)
	return s.tail(elements)
}

// tail is asset, net and gross per public slot, the withdrawal hash, the element count and the nonzero version.
func (s Statement) tail(elements []*big.Int) []*big.Int {
	for k := range s.PublicAssets {
		elements = append(elements, s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k])
	}
	elements = append(elements, s.WithdrawalHash)
	return append(elements, big.NewInt(int64(len(elements)+2)), big.NewInt(shared.TransferStatementVersion))
}

func bitField(set bool) *big.Int {
	if set {
		return big.NewInt(1)
	}
	return big.NewInt(0)
}
