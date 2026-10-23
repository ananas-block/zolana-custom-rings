package ringprotocol

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

// DisclosurePad mirrors shared.DisclosurePad under one seed domain.
func DisclosurePad(t testing.TB, domain uint64, key [32]byte, salt [16]byte, n int) []*big.Int {
	t.Helper()
	keyLo, keyHi := Pack32(key)
	seed := ringtest.MustPoseidonHash(t, new(big.Int).SetUint64(domain), keyLo, keyHi, new(big.Int).SetBytes(salt[:]))
	pad := make([]*big.Int, n)
	for i := range pad {
		pad[i] = ringtest.MustPoseidonHash(t, seed, big.NewInt(int64(i)))
	}
	return pad
}

// PackDisclosure mirrors shared.PackDisclosure, the short last chunk keeps its bytes first.
func PackDisclosure(bytes []byte) []*big.Int {
	const chunk = 31
	padded := append(append([]byte{}, bytes...), make([]byte, (chunk-len(bytes)%chunk)%chunk)...)
	fields := make([]*big.Int, len(padded)/chunk)
	for i := range fields {
		fields[i] = new(big.Int).SetBytes(padded[i*chunk : (i+1)*chunk])
	}
	return fields
}
