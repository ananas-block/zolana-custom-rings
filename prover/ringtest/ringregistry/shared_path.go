package ringregistry

import (
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
)

func (r *Registry) SharedProof(indices []uint64) (registry.SharedQuadProof, error) {
	proof, err := registry.NewSharedQuadProof(len(indices))
	if err != nil {
		return registry.SharedQuadProof{}, err
	}
	depth := len(proof.Paths[0].Siblings)
	for i := range proof.Canopy {
		proof.Canopy[i] = new(big.Int).Set(r.node(depth, uint64(i)))
	}
	for i, index := range indices {
		if index >= registry.Capacity {
			return registry.SharedQuadProof{}, fmt.Errorf("registry leaf index outside capacity")
		}
		path := r.Path(index)
		proof.Paths[i].Index = index
		for level := range proof.Paths[i].Siblings {
			for child, sibling := range path.Siblings[level] {
				proof.Paths[i].Siblings[level][child] = new(big.Int).Set(sibling)
			}
		}
	}
	return proof, nil
}
