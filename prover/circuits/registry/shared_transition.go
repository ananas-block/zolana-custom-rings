package registry

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/selector"
)

type RootTransition struct {
	Old, New frontend.Variable
}

type LeafChange struct {
	Enabled       frontend.Variable
	Before, After frontend.Variable
}

func (p SharedQuadProof) AssertChanges(api frontend.API, roots RootTransition, changes []LeafChange) error {
	if err := p.validate(len(changes)); err != nil {
		return err
	}
	api.AssertIsEqual(canopyRoot(api, p.Canopy), roots.Old)
	nodes := append([]frontend.Variable(nil), p.Canopy...)
	for i, change := range changes {
		api.AssertIsBoolean(change.Enabled)
		path := p.Paths[i]
		bits := api.ToBinary(path.Index, IndexBits)
		before := foldQuadPath(api, path.Siblings, bits, change.Before)
		after := foldQuadPath(api, path.Siblings, bits, change.After)
		index := frontend.Variable(0)
		if len(path.Siblings) < Height {
			index = api.FromBinary(bits[2*len(path.Siblings):]...)
		}
		selected := selector.Decoder(api, len(nodes), index)
		old := frontend.Variable(0)
		for j, flag := range selected {
			old = api.MulAcc(old, flag, nodes[j])
		}
		api.AssertIsEqual(api.Mul(change.Enabled, api.Sub(old, before)), 0)
		delta := api.Mul(change.Enabled, api.Sub(after, before))
		for j, flag := range selected {
			nodes[j] = api.MulAcc(nodes[j], flag, delta)
		}
	}
	api.AssertIsEqual(canopyRoot(api, nodes), roots.New)
	return nil
}
