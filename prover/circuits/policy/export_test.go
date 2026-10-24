package policy

import "github.com/consensys/gnark/frontend"

func DecodeTable(t Table, api frontend.API, rc frontend.Rangechecker, policyHash frontend.Variable) {
	t.decode(api, rc, policyHash)
}
