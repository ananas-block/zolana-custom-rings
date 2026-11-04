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
	privateTxBlinding = 0x5b1d
	publishedInputs   = 2
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

// Addresses holds the bound address hash per owner identity on an anonymous rail.
type policyFixture struct {
	Policy      Policy
	Exempt      bool
	Escrow      bool
	Published   bool
	Delivery    bool
	Outputs     []ringaudit.Utxo
	Wires       []shared.UtxoWires
	Public      []PublicSlot
	Withdrawals []Withdrawal
	// Senders fills the key's sender rows, the first the fixture sender.
	Senders       []frontend.Variable
	RingProgramID *big.Int
	Addresses     map[string]*big.Int
	// FrozenCoOwner puts the second sender row on the frozen list.
	FrozenCoOwner bool
}

// registries enrols every sender and UTXO output owner on the allow list, escrows them under escrow, binds their addresses, and limits the fixture asset.
func (f policyFixture) registries(t testing.TB) (own, curator *ringregistry.Registry) {
	t.Helper()
	own, curator = ringregistry.New(t), ringregistry.New(t)
	zero := big.NewInt(0)
	seen := map[string]bool{}
	member := func(identity, nullifierPk *big.Int, lists uint64) {
		if seen[identity.String()] {
			return
		}
		seen[identity.String()] = true
		bits := new(big.Int).SetUint64(lists)
		own.Apply(t, ringregistry.Entry{Member: identity, Mask: bits, Value: bits, MintPolicy: zero, WithdrawalThreshold: zero})
	}
	for j, sender := range f.Senders {
		identity := ringtest.AsBigInt(sender)
		if identity.Sign() == 0 {
			continue
		}
		lists := uint64(ringregistry.AllowBit)
		if (j == 0 && f.Policy.Frozen) || (j == 1 && f.FrozenCoOwner) {
			lists |= ringregistry.FrozenBit
		}
		member(identity, spptest.MustNullifierPk(t, big.NewInt(7)), lists)
	}
	for _, output := range f.Outputs {
		if output.IsUtxo() {
			member(output.OwnerPkHash, output.NullifierPk, ringregistry.AllowBit)
		}
	}
	for _, leg := range f.Withdrawals {
		member(leg.Owner, nil, ringregistry.AllowBit)
	}
	p := f.Policy
	// Bit 192 writes the mint policy, cap at 2^64 and the co-sign bound below it.
	mintPolicy := new(big.Int).Lsh(big.NewInt(1), 192)
	mintPolicy.Or(mintPolicy, new(big.Int).Lsh(new(big.Int).SetUint64(p.Cap), 64))
	mintPolicy.Or(mintPolicy, new(big.Int).SetUint64(p.CosignAbove))
	own.Apply(t, ringregistry.Entry{Member: Asset(t), Mask: zero, Value: zero, MintPolicy: mintPolicy, WithdrawalThreshold: new(big.Int).SetUint64(p.Threshold)})
	return own, curator
}

// fill sets every statement value of the policy section and opens its pools.
func (f policyFixture) fill(t testing.TB, p *policy.Policy) (own, curator *ringregistry.Registry) {
	t.Helper()
	own, curator = f.registries(t)
	p.Table = table()
	p.PolicyHash, p.OwnRoot, p.CuratorRoot = 0, 0, 0
	if f.Policy.Screened {
		p.PolicyHash = ringpolicy.TableHash(t, p.Table)
	}
	if f.Policy.Screened || f.Exempt || f.Escrow || f.Delivery {
		p.OwnRoot = own.Root()
	}
	p.RingProgramID = f.RingProgramID
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = 0, 0, 0
		if k < len(f.Public) {
			p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = f.Public[k].Asset, protocol.SignedToField(big.NewInt(f.Public[k].Net)), new(big.Int).SetUint64(f.Public[k].Gross)
		}
	}
	p.WithdrawalCount = len(f.Withdrawals)
	for i := range p.Withdrawals {
		p.Withdrawals[i] = policy.WithdrawalWires{Owner: 0, Asset: 0, Amount: 0}
		if i < len(f.Withdrawals) {
			p.Withdrawals[i] = policy.WithdrawalWires{Owner: f.Withdrawals[i].Owner, Asset: f.Withdrawals[i].Asset, Amount: new(big.Int).SetUint64(f.Withdrawals[i].Amount)}
		}
	}
	for o, output := range f.Outputs {
		p.CtHashes[o], p.Recipients[o] = 0, 0
		if output.IsUtxo() {
			p.CtHashes[o] = ctHash(output.OwnerPkHash)
			if f.Policy.Screened && f.Published {
				p.Recipients[o] = output.OwnerPkHash
			}
		}
	}
	ringpolicy.FillPools(t, p, f.Wires, f.Senders, own, curator)
	return own, curator
}

func senderRows(rows int, owners ...*big.Int) []frontend.Variable {
	cells := make([]frontend.Variable, rows)
	for j := range cells {
		cells[j] = 0
		if j < len(owners) {
			cells[j] = owners[j]
		}
	}
	return cells
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
