package ringtest

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func Bit(set bool) int64 {
	if set {
		return 1
	}
	return 0
}

func MustSolanaPkField(t testing.TB, key [32]byte) *big.Int {
	t.Helper()
	value, err := protocol.SolanaPkField(key)
	return spptest.MustHash(t, value, err)
}

func MustPoseidonHash(t testing.TB, inputs ...*big.Int) *big.Int {
	t.Helper()
	value, err := poseidon.Hash(inputs)
	return spptest.MustHash(t, value, err)
}

// AsBigInt also takes the uint64 values the ring builders assign.
func AsBigInt(value frontend.Variable) *big.Int {
	if v, ok := value.(uint64); ok {
		return new(big.Int).SetUint64(v)
	}
	return spptest.AsBigInt(value)
}

func ToBigInts(values []frontend.Variable) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, value := range values {
		out[i] = AsBigInt(value)
	}
	return out
}
