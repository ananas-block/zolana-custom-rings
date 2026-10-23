package ringgadget

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

const byteBits = 8

// BoundedBytes skips the byte check, for bytes the caller constrains to 8 bits where they are produced.
type BoundedBytes struct{}

func (BoundedBytes) Check(frontend.Variable, int) {}

// RingOutputBlindingDomainV1 = "TXRB".
const RingOutputBlindingDomainV1 = 0x54585242

// DeriveRingOutputBlinding is bound by the ring's audit proof, never by SPP.
func DeriveRingOutputBlinding(api frontend.API, firstNullifier, ringSecret, outputIndex frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{RingOutputBlindingDomainV1, firstNullifier, ringSecret, outputIndex})
}

// DeriveRingRailOutputBlinding is TXOB over seed when inDefaultRing is 1 and TXRB over ringSecret when it is 0.
func DeriveRingRailOutputBlinding(api frontend.API, inDefaultRing, firstNullifier, seed, ringSecret frontend.Variable, outputIndex int) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{
		api.Select(inDefaultRing, shared.OutputBlindingDomainV1, RingOutputBlindingDomainV1),
		firstNullifier,
		api.Select(inDefaultRing, seed, ringSecret),
		outputIndex,
	})
}

// PrivateTxHashFromChains requires each chain to be the NonZeroHashChain of its slot list.
func PrivateTxHashFromChains(api frontend.API, inputChain, outputChain, addressChain, blinding frontend.Variable) frontend.Variable {
	return gadget.PoseidonHash(api, []frontend.Variable{inputChain, outputChain, addressChain, blinding})
}

func IsConstantZero(api frontend.API, v frontend.Variable) bool {
	value, ok := api.Compiler().ConstantValue(v)
	return ok && value.Sign() == 0
}
