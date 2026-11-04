package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

// Statement is what the program holds for a transfer statement.
type Statement struct {
	Head ringaudit.AuditHead
	// RailBits are in_proof, delegate on the confidential family, public_owners, delegate on the anonymous one.
	RailBits      [2]bool
	ApprovalMask  *big.Int
	NoSpend       bool
	Outputs       []ringaudit.StatementOutput
	InputCount    int
	PrivateTxHash *big.Int
	// Cells are the sender or the seven party identities.
	Cells                                                       []*big.Int
	SignerCount                                                 int
	SignerChain                                                 *big.Int
	PolicyHash, OwnRoot, CuratorRoot, TrackingRoot, PrivateRoot *big.Int
	PublicAssets, PublicNets, PublicGross                       [3]*big.Int
	WithdrawalHash                                              *big.Int
}

// Elements mirrors TransferStatement::elements.
func (s Statement) Elements(t testing.TB) []*big.Int {
	t.Helper()
	elements := append(s.Head.ElementsUnder(t, shared.TransferStatementDomain),
		bitField(s.RailBits[0]), bitField(s.RailBits[1]), s.ApprovalMask, bitField(s.NoSpend),
		big.NewInt(int64(ringaudit.OutputCount(s.Outputs))),
		ringaudit.OutputChain(t, s.Outputs), ringaudit.RecordChain(t, s.Outputs), ringaudit.TailChain(t, s.Outputs),
		big.NewInt(int64(s.InputCount)), s.PrivateTxHash,
	)
	elements = append(elements, s.Cells...)
	elements = append(elements, big.NewInt(int64(s.SignerCount)), s.SignerChain, s.PolicyHash, s.OwnRoot, s.CuratorRoot, s.TrackingRoot, s.PrivateRoot)
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
