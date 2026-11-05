package ringregistry

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

// ListTag mirrors shared.ListTag.
func ListTag(t testing.TB, listSalt *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListTagDomain), listSalt)
}

func ListKey(t testing.TB, owner, listSalt *big.Int) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, big.NewInt(shared.ListKeyDomain), owner, listSalt)
}
