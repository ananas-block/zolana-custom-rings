package ringregistry

import (
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
)

func (e Entry) Wires() registry.RecordWrite {
	return registry.RecordWrite{
		Member: copied(e.Member), Mask: copied(e.Mask), Value: copied(e.Value),
		MintPolicy: copied(e.MintPolicy), WithdrawalThreshold: copied(e.WithdrawalThreshold), AssetLimits: e.AssetLimits.Wires(),
	}
}

func (w Write) Wires() registry.RecordWriteProofInput {
	return registry.RecordWriteProofInput{
		Entry: w.Entry.Wires(), Exists: ringtest.Bit(w.Exists),
		Old: registry.RecordBody{
			Next: copied(w.OldNext), Lists: copied(w.OldLists), MintPolicy: copied(w.OldMintPolicy),
			WithdrawalThreshold: copied(w.OldWithdrawalThreshold), AssetLimits: w.OldAssetLimits.Wires(),
		},
		Slot: w.Slot.Wires(), Low: w.Low.Wires(), LowSlot: w.LowPath.Wires(),
	}
}
