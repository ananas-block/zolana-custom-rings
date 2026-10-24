// Package ringtest holds the host helpers and fixtures the ring twin packages share.
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

// AssetField is hash_bytes(asset_address).
func AssetField(t testing.TB, assetAddress [32]byte) *big.Int {
	t.Helper()
	asset, err := protocol.AssetField(assetAddress)
	return spptest.MustHash(t, asset, err)
}

// Scalar is byte i = seed ^ i with a 0x01 lead byte, mirrored by scalar in sdk-libs/client/tests/common/transfer.rs.
func Scalar(seed byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	out[0] = 0x01
	return out
}

// Repeat is 32 copies of one byte.
func Repeat(value byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = value
	}
	return out
}

func HashBytes(t testing.TB, bytes []byte) *big.Int {
	t.Helper()
	hash, err := protocol.HashBytes(bytes)
	return spptest.MustHash(t, hash, err)
}

func SetBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}
