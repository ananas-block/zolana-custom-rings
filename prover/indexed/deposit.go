package indexed

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/deposit"
	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	zolana "github.com/helius-labs/zolana/prover/server/prover/indexed"
	"github.com/helius-labs/zolana/prover/server/prover/timing"
)

func decodeDepositRequest(data []byte) (zolana.Resolution, error) {
	request, params, err := decodeDeposit(data)
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, r *zolana.Resolver) (*zolana.Resolved, error) {
		return resolveDeposit(ctx, r, request, params)
	}, nil
}

func decodeDeposit(data []byte) (request, *ring.DepositParameters, error) {
	var request request
	if err := zolana.DecodeEnvelope(data, &request); err != nil {
		return request, nil, err
	}
	if request.CircuitType != ring.CustomRingDepositCircuitType || len(request.Trees) != 0 || len(request.Inputs) != 0 || len(request.PublicInputs) != 1 {
		return request, nil, fmt.Errorf("invalid indexed deposit")
	}
	var base map[string]json.RawMessage
	if json.Unmarshal(request.Prepared, &base) != nil || base == nil || base["keys"] != nil {
		return request, nil, fmt.Errorf("invalid prepared deposit")
	}
	if err := validateRegistryAnchor(base, request.Registry); err != nil {
		return request, nil, err
	}
	var count uint32
	if json.Unmarshal(base["count"], &count) != nil || count < 1 || count > deposit.MaxDeposits {
		return request, nil, fmt.Errorf("invalid deposit count")
	}
	keys := make([]json.RawMessage, deposit.MaxDeposits)
	for i := range keys {
		keys[i] = json.RawMessage("null")
		if i < int(count) {
			keys[i] = registryPlaceholder()
		}
	}
	base["keys"], _ = json.Marshal(keys)
	prepared, err := json.Marshal(base)
	if err != nil {
		return request, nil, err
	}
	var params ring.DepositParameters
	if err := json.Unmarshal(prepared, &params); err != nil {
		return request, nil, err
	}
	expected, err := common.FeFromHex(request.PublicInputs[0])
	if err != nil || !params.KeyEscrow.Enabled || expected.Cmp(params.PublicInputHash) != 0 {
		return request, nil, fmt.Errorf("deposit statement mismatch")
	}
	return request, &params, nil
}

func resolveDeposit(ctx context.Context, r *zolana.Resolver, request request, params *ring.DepositParameters) (*zolana.Resolved, error) {
	release, err := r.Admit(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	finish := timing.FromContext(ctx).Start("indexer_fetch")
	defer finish()
	keys := make(map[zolana.Hash]*ring.RegistryKey)
	for i := range int(params.Count) {
		params.Keys[i], err = registryKey(ctx, r, request, keys, params.OwnerPkHashes[i], params.NullifierPks[i])
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return &zolana.Resolved{Payload: payload, Resolution: &common.ProofResolution{Trees: []common.ResolvedTree{}, PublicInputHash: common.FeHex(params.PublicInputHash)}}, nil
}
