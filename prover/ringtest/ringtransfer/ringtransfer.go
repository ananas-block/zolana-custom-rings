// Package ringtransfer builds honest witnesses of the transfer keys from the audit and policy fixtures.
package ringtransfer

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	// inputChain is SPP's input chain of a signer-rail transfer, opaque to the proof.
	inputChain        = 0x1c
	privateTxBlinding = 0x5b1d
)

// PublicSlot is one folded public slot, Gross the withdrawn total of its asset.
type PublicSlot struct {
	Asset *big.Int
	Net   int64
	Gross uint64
}

type Withdrawal struct {
	Owner, Asset *big.Int
	Amount       uint64
}

// Policy is the ring's table and the fixture asset's limits, Screened off on an audit-only ring.
type Policy struct {
	Screened bool
	// Cap and CosignAbove bound the fixture asset's outflow, Threshold its exemption.
	Cap, CosignAbove, Threshold uint64
	// Frozen freezes the sender, the one rule a sender fails.
	Frozen bool
}

// Asset is the fixture asset of every ring output and spent note.
func Asset(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.AssetField(t, ringtest.Repeat(0x0a))
}

// Sender is the identity of the fixture sender key.
func Sender(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustSolanaPkField(t, ringtest.Repeat(0xa1))
}

// table admits every output owner on the allow list and refuses a frozen sender.
func table() policy.Table {
	rules := []ringpolicy.Rule{ringpolicy.Require(policy.SubjectOutputOwner, ringregistry.AllowBit), ringpolicy.Forbid(policy.SubjectSender, ringregistry.FrozenBit)}
	return ringpolicy.Table{Lists: []uint64{ringregistry.AllowBit, ringregistry.BlockBit, ringregistry.FrozenBit}, Rules: rules}.Wires()
}

// ctHash is the escrowed key ciphertext hash of an owner, one per owner.
func ctHash(owner *big.Int) *big.Int {
	return new(big.Int).Add(owner, big.NewInt(0x66))
}

// registries enrols the sender and every UTXO output owner on the allow list, escrows them under escrow, and limits the fixture asset.
func registries(t testing.TB, p Policy, sender *big.Int, outputs []ringaudit.Utxo, withdrawals []Withdrawal, escrow bool) (own, curator *ringregistry.Registry) {
	t.Helper()
	own, curator = ringregistry.New(t), ringregistry.New(t)
	zero := big.NewInt(0)
	member := func(identity, nullifierPk *big.Int, lists uint64) {
		escrowKey := zero
		if escrow && nullifierPk != nil {
			escrowKey = ringregistry.EscrowKey(t, nullifierPk, ctHash(identity))
		}
		bits := new(big.Int).SetUint64(lists)
		own.Apply(t, ringregistry.Entry{Member: identity, Mask: bits, Value: bits, EscrowKey: escrowKey, MintPolicy: zero, WithdrawalThreshold: zero})
	}
	senderLists := uint64(ringregistry.AllowBit)
	if p.Frozen {
		senderLists |= ringregistry.FrozenBit
	}
	member(sender, spptest.MustNullifierPk(t, big.NewInt(7)), senderLists)
	for _, output := range outputs {
		if output.IsUtxo() && output.OwnerPkHash.Cmp(sender) != 0 {
			member(output.OwnerPkHash, output.NullifierPk, ringregistry.AllowBit)
		}
	}
	for _, leg := range withdrawals {
		if leg.Owner.Cmp(sender) != 0 {
			member(leg.Owner, nil, ringregistry.AllowBit)
		}
	}
	// Bit 192 writes the mint policy, cap at 2^64 and the co-sign bound below it.
	mintPolicy := new(big.Int).Lsh(big.NewInt(1), 192)
	mintPolicy.Or(mintPolicy, new(big.Int).Lsh(new(big.Int).SetUint64(p.Cap), 64))
	mintPolicy.Or(mintPolicy, new(big.Int).SetUint64(p.CosignAbove))
	own.Apply(t, ringregistry.Entry{Member: Asset(t), Mask: zero, Value: zero, EscrowKey: zero, MintPolicy: mintPolicy, WithdrawalThreshold: new(big.Int).SetUint64(p.Threshold)})
	return own, curator
}

// fillPolicy sets every statement value of the policy section and opens its pools.
func fillPolicy(t testing.TB, p *policy.Policy, w Policy, exempt, escrow bool, outputs []ringaudit.Utxo, wires []shared.UtxoWires, public []PublicSlot, withdrawals []Withdrawal, sender *big.Int, published bool, ringProgramID *big.Int) (own, curator *ringregistry.Registry) {
	t.Helper()
	own, curator = registries(t, w, sender, outputs, withdrawals, escrow)
	p.Table = table()
	p.PolicyHash, p.OwnRoot, p.CuratorRoot = 0, 0, 0
	if w.Screened {
		p.PolicyHash = ringpolicy.TableHash(t, p.Table)
	}
	if w.Screened || exempt || escrow {
		p.OwnRoot = own.Root()
	}
	p.RingProgramID = ringProgramID
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = 0, 0, 0
		if k < len(public) {
			p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = public[k].Asset, protocol.SignedToField(big.NewInt(public[k].Net)), new(big.Int).SetUint64(public[k].Gross)
		}
	}
	p.WithdrawalCount = len(withdrawals)
	for i := range p.Withdrawals {
		p.Withdrawals[i] = policy.WithdrawalWires{Owner: 0, Asset: 0, Amount: 0}
		if i < len(withdrawals) {
			p.Withdrawals[i] = policy.WithdrawalWires{Owner: withdrawals[i].Owner, Asset: withdrawals[i].Asset, Amount: new(big.Int).SetUint64(withdrawals[i].Amount)}
		}
	}
	for o, output := range outputs {
		p.CtHashes[o], p.Recipients[o] = 0, 0
		if output.IsUtxo() {
			p.CtHashes[o] = ctHash(output.OwnerPkHash)
			if w.Screened && published {
				p.Recipients[o] = output.OwnerPkHash
			}
		}
	}
	ringpolicy.FillPools(t, p, wires, sender, own, curator)
	return own, curator
}

// withdrawalHash mirrors policy openWithdrawals over the live legs.
func withdrawalHash(t testing.TB, p *policy.Policy) *big.Int {
	t.Helper()
	fields := []*big.Int{big.NewInt(shared.WithdrawalsDomain), ringtest.AsBigInt(p.WithdrawalCount)}
	for _, leg := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		fields = append(fields, ringtest.AsBigInt(leg.Owner), ringtest.AsBigInt(leg.Asset), ringtest.AsBigInt(leg.Amount))
	}
	return spptest.MustHashChain4(t, fields)
}

// policyStatement is the policy section's part of the statement as the witness holds it.
func policyStatement(p *policy.Policy) Statement {
	s := Statement{
		PolicyHash: ringtest.AsBigInt(p.PolicyHash),
		OwnRoot:    ringtest.AsBigInt(p.OwnRoot), CuratorRoot: ringtest.AsBigInt(p.CuratorRoot),
		Recipients: ringtest.ToBigInts(p.Recipients), WithdrawalHash: ringtest.AsBigInt(p.WithdrawalHash),
	}
	for k := range p.PublicAssets {
		s.PublicAssets[k], s.PublicNets[k], s.PublicGross[k] = ringtest.AsBigInt(p.PublicAssets[k]), ringtest.AsBigInt(p.PublicAmounts[k]), ringtest.AsBigInt(p.PublicGross[k])
	}
	return s
}

func bit(set bool) frontend.Variable {
	return ringtest.Bit(set)
}
