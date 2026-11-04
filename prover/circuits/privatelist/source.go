package privatelist

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
)

// Source enters the policy table, mirrored by PrivateSource in program-libs/policy/src/private_source.rs.
type Source struct {
	// OwnerLists marks the slots owner rows read from Registry, asset rows always keep the public slot.
	OwnerLists frontend.Variable
	Registry   frontend.Variable
}

// Fields keeps the table hash order.
func (s Source) Fields() []frontend.Variable {
	return []frontend.Variable{s.OwnerLists, s.Registry}
}

type SourceView struct {
	private [NLists]frontend.Variable
	// Any activates the private root and the row pool.
	Any frontend.Variable
}

func (s Source) View(api frontend.API) SourceView {
	return SourceView{private: [NLists]frontend.Variable(api.ToBinary(s.OwnerLists, NLists)), Any: ringgadget.IsNonZero(api, s.OwnerLists)}
}

// OwnerRow picks an owner row's bit from the private read on its marked slots.
func (v SourceView) OwnerRow(api frontend.API, public, private [NLists]frontend.Variable) [NLists]frontend.Variable {
	var onList [NLists]frontend.Variable
	for i := range onList {
		onList[i] = api.Select(v.private[i], private[i], public[i])
	}
	return onList
}
