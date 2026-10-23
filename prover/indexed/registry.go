package indexed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ring"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	zolana "github.com/helius-labs/zolana/prover/server/prover/indexed"
	"github.com/helius-labs/zolana/prover/server/prover/transcript"
)

type RegistryRequest struct {
	Ring      zolana.Hash `json:"ringProgramId"`
	Root      zolana.Hash `json:"root"`
	NextIndex uint64      `json:"nextIndex"`
}

type request struct {
	zolana.Request
	Registry *RegistryRequest `json:"registry,omitempty"`
}

func init() {
	zolana.Register(ring.CustomRingDepositCircuitType, decodeDepositRequest)
	for _, circuit := range policyCircuits {
		zolana.Register(circuit, decodePolicyRequest)
	}
}

func prepareRegistry(base map[string]json.RawMessage, request *RegistryRequest) error {
	var enabled bool
	if json.Unmarshal(base["keyEscrow"], &enabled) != nil || enabled != (request != nil) {
		return fmt.Errorf("invalid registry request")
	}
	var outputs []map[string]json.RawMessage
	if json.Unmarshal(base["outputs"], &outputs) != nil {
		return fmt.Errorf("invalid policy outputs")
	}
	for _, output := range outputs {
		if output == nil || output["key"] != nil {
			return fmt.Errorf("prepared output contains registry witness")
		}
	}
	if !enabled {
		return nil
	}
	if err := validateRegistryAnchor(base, request); err != nil {
		return err
	}
	// 1. Registry placeholders remain internal until membership is verified.
	for _, output := range outputs {
		output["key"] = registryPlaceholder()
	}
	base["outputs"], _ = json.Marshal(outputs)
	return nil
}

func validateRegistryAnchor(base map[string]json.RawMessage, request *RegistryRequest) error {
	if request == nil {
		return fmt.Errorf("missing registry anchor")
	}
	root, err := request.Root.Field()
	if err != nil || request.NextIndex < 1 || request.NextIndex > 1<<registry.Height {
		return fmt.Errorf("invalid registry anchor")
	}
	var encoded string
	if json.Unmarshal(base["keyRegistryRoot"], &encoded) != nil {
		return fmt.Errorf("invalid registry root")
	}
	expected, err := common.FeFromHex(encoded)
	if err != nil || root.Cmp(expected) != 0 {
		return fmt.Errorf("registry root mismatch")
	}
	return nil
}

func registryPlaceholder() json.RawMessage {
	zero := common.ToHex(new(big.Int))
	path := make([]string, registry.Height)
	for i := range path {
		path[i] = zero
	}
	value, _ := json.Marshal(map[string]any{"next": zero, "ctHash": zero, "index": 0, "path": path})
	return value
}

func unregistered(member zolana.Hash, outcome string) error {
	return &zolana.Rejection{Outcome: outcome, Code: "registry_member_missing", Message: "Output owner has no registered key", Detail: map[string]string{"member": member.String()}}
}

type registryEntry struct {
	Context struct {
		Slot uint64 `json:"slot"`
	} `json:"context"`
	Root       zolana.Hash   `json:"root"`
	Member     zolana.Hash   `json:"member"`
	Next       zolana.Hash   `json:"next"`
	NextIndex  uint64        `json:"nextIndex"`
	Index      uint64        `json:"index"`
	Ciphertext []byte        `json:"ciphertext"`
	Proof      []zolana.Hash `json:"proof"`
}

func resolvePolicyRegistry(ctx context.Context, r *zolana.Resolver, request request, policy *resolvedPolicy) error {
	if request.Registry == nil {
		return nil
	}
	keys := make(map[zolana.Hash]*ring.RegistryKey)
	for i := range policy.base.Outputs {
		output := &policy.base.Outputs[i]
		output.Key = nil
		if i >= int(policy.base.NOut) || output.Domain.Cmp(big.NewInt(shared.UtxoDomain)) != 0 {
			continue
		}
		owner, err := transcript.HashFields([]*big.Int{output.OwnerPkHash, output.NullifierPk})
		if err != nil {
			return err
		}
		if owner.Cmp(policy.base.NamespaceOwnerHash) == 0 {
			continue
		}
		key, err := registryKey(ctx, r, request, keys, output.OwnerPkHash, output.NullifierPk)
		if err != nil {
			return err
		}
		output.Key = key
	}
	return nil
}

func registryKey(ctx context.Context, r *zolana.Resolver, request request, keys map[zolana.Hash]*ring.RegistryKey, owner, nullifier *big.Int) (*ring.RegistryKey, error) {
	anchor := request.Registry
	member, err := zolana.HashField(owner)
	if err != nil || owner.Sign() == 0 {
		return nil, fmt.Errorf("invalid registry owner")
	}
	// 2. The membership leaf binds both the owner and its expected nullifier key.
	if known := keys[member]; known != nil {
		if verifyRegistryKey(member, nullifier, known, anchor.Root) != nil {
			return nil, unregistered(member, "mismatch")
		}
		return known, nil
	}
	payload, err := r.RPC(ctx, "getRingKeyRegistryEntry", map[string]any{"ringProgramId": anchor.Ring, "member": member, "expectedRoot": anchor.Root, "expectedNextIndex": anchor.NextIndex})
	var failure *zolana.RPCError
	if errors.As(err, &failure) {
		switch failure.Code {
		case -32070, -32071:
			return nil, zolana.ErrIndexerNotReady
		case -32072:
			return nil, unregistered(member, "rejected")
		}
	}
	if err != nil {
		return nil, err
	}
	var entry registryEntry
	if json.Unmarshal(payload, &entry) != nil || entry.Root != anchor.Root || entry.Member != member || entry.NextIndex != anchor.NextIndex || entry.Index == 0 || entry.Index >= entry.NextIndex || len(entry.Proof) != registry.Height || len(entry.Ciphertext) != 32 {
		return nil, fmt.Errorf("invalid registry membership")
	}
	next, err := entry.Next.Field()
	if err != nil {
		return nil, err
	}
	ciphertext, err := transcript.HashFields([]*big.Int{new(big.Int).SetBytes(entry.Ciphertext[:31]), new(big.Int).SetBytes(entry.Ciphertext[31:])})
	if err != nil {
		return nil, err
	}
	key := &ring.RegistryKey{Next: next, CtHash: ciphertext, Index: entry.Index}
	for level, sibling := range entry.Proof {
		key.Path[level], err = sibling.Field()
		if err != nil {
			return nil, err
		}
	}
	// A corrupt indexer path is indistinguishable from a key mismatch here.
	if verifyRegistryKey(member, nullifier, key, anchor.Root) != nil {
		return nil, unregistered(member, "mismatch")
	}
	if entry.Context.Slot < request.MinContextSlot {
		return nil, zolana.ErrIndexerNotReady
	}
	keys[member] = key
	return key, nil
}

func verifyRegistryKey(member zolana.Hash, nullifier *big.Int, key *ring.RegistryKey, root zolana.Hash) error {
	keyHash, err := transcript.HashFields([]*big.Int{nullifier, key.CtHash})
	if err != nil {
		return err
	}
	owner, err := member.Field()
	if err != nil {
		return err
	}
	leaf, err := transcript.HashFields([]*big.Int{owner, key.Next, keyHash})
	if err != nil {
		return err
	}
	hash, err := zolana.HashField(leaf)
	if err != nil {
		return err
	}
	path := make([]zolana.Hash, registry.Height)
	for level, sibling := range key.Path {
		path[level], err = zolana.HashField(sibling)
		if err != nil {
			return err
		}
	}
	return zolana.VerifyPath(hash, path, key.Index, root)
}
