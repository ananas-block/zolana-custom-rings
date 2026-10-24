package ringpolicy

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	circuitregistry "github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

type Witness struct {
	Member   *policy.MemberPolicyCircuit
	Delegate *policy.DelegatePolicyCircuit
}

func (w World) Build(t testing.TB) Witness {
	t.Helper()
	return w.BuildRows(t, w.Table.rows())
}

// BuildRows builds the world under rows in place of Table's, the table a vector carries.
func (w World) BuildRows(t testing.TB, rows Rows) Witness {
	t.Helper()
	var b Witness
	if w.Outputs != 0 {
		c, err := policy.NewMemberPolicyCircuitWith(policy.MemberShape{Outputs: w.Outputs, Withdrawals: w.WithdrawalCapacity, OwnOnly: w.OwnOnly})
		if err != nil {
			t.Fatal(err)
		}
		b.Member = c
	} else {
		c, err := policy.NewDelegatePolicyCircuitWith(policy.DelegateShape{Shape: w.Shape, OwnOnly: w.OwnOnly})
		if err != nil {
			t.Fatal(err)
		}
		b.Delegate = c
	}
	p := b.Policy()
	own, curator := registry(t, w.Own), registry(t, w.Curator)
	entry := func(member int64) policy.Entry {
		e := policy.Entry{Own: own.Opening(big.NewInt(member)).Wires()}
		if !w.OwnOnly {
			e.Curator = []circuitregistry.QuadOpening{curator.Opening(big.NewInt(member)).Wires()}
		}
		return e
	}
	p.Table = rows.Wires()
	p.PolicyHash = TableHash(t, p.Table)
	p.RingProgramID, p.OwnRoot, p.CuratorRoot = ringID, own.Root(), 0
	if slices.ContainsFunc(rows.Sources, func(s policy.SourceWires) bool { return ringtest.AsBigInt(s.Registry).Sign() != 0 }) {
		p.CuratorRoot = curator.Root()
	}
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k] = 0, 0
		if k < len(w.Public) {
			p.PublicAssets[k], p.PublicAmounts[k] = w.Public[k].Asset, protocol.SignedToField(big.NewInt(w.Public[k].Amount))
		}
	}
	p.AddressChain, p.PrivateTxBlinding, p.SenderPkHash = 0, privateTxBlinding, w.Sender
	p.SenderEntry = entry(w.Sender)
	for o := range p.Outputs {
		s := pick(w.Slots, o)
		p.Outputs[o] = policy.OutputWires{UtxoWires: s.wires(0xb100 + int64(o)), CtHash: 0}
		if s.Owner != 0 {
			p.Outputs[o].CtHash = ctHash(s.Owner)
		}
		p.OwnerEntries[o], p.AssetEntries[o] = entry(s.Owner), entry(s.Asset)
	}
	p.WithdrawalCount = len(w.Withdrawals)
	for i := range p.Withdrawals {
		s := pick(w.Withdrawals, i)
		p.Withdrawals[i] = policy.WithdrawalWires{Owner: s.Owner, Asset: s.Asset, Amount: s.Amount}
		p.OwnerEntries[len(p.Outputs)+i], p.AssetEntries[len(p.Outputs)+i] = entry(s.Owner), entry(s.Asset)
	}
	if b.Delegate != nil {
		for i := range b.Delegate.Inputs {
			b.Delegate.Inputs[i] = pick(w.Inputs, i).wires(0xa100 + int64(i))
		}
	}
	if c := b.Member; c != nil {
		c.InputChain = inputChain
		c.Anonymous, c.KeyEscrow, c.ApprovalRequired = ringtest.Bit(w.Anonymous), ringtest.Bit(w.KeyEscrow), ringtest.Bit(w.ApprovalRequired)
		c.Sender = big.NewInt(w.Sender)
		if w.Anonymous {
			c.Sender = ringprotocol.SenderCommitment(t, big.NewInt(w.Sender), big.NewInt(privateTxBlinding))
		}
	}
	b.Rehash(t)
	return b
}

func (b Witness) Policy() *policy.Policy {
	if b.Member != nil {
		return &b.Member.Policy
	}
	return &b.Delegate.Policy
}

func (b Witness) Assignment() frontend.Circuit {
	if b.Member != nil {
		return b.Member
	}
	return b.Delegate
}

// Rehash recomputes private_tx_hash from the slot wires after one changes, then the public input.
func (b Witness) Rehash(t testing.TB) {
	t.Helper()
	p := b.Policy()
	outputs := make([]*big.Int, len(p.Outputs))
	for o, w := range p.Outputs {
		outputs[o] = utxoHash(t, w.UtxoWires)
	}
	var chain *big.Int
	if b.Member != nil {
		chain = ringtest.AsBigInt(b.Member.InputChain)
	} else {
		inputs := make([]*big.Int, len(b.Delegate.Inputs))
		for i, w := range b.Delegate.Inputs {
			inputs[i] = utxoHash(t, w)
		}
		chain = spptest.MustNonZeroHashChain(t, inputs)
	}
	p.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{chain, spptest.MustNonZeroHashChain(t, outputs), ringtest.AsBigInt(p.AddressChain), ringtest.AsBigInt(p.PrivateTxBlinding)})
	b.Rebind(t)
}

// Rebind recomputes the public input after a statement value changes.
func (b Witness) Rebind(t testing.TB) {
	t.Helper()
	p := b.Policy()
	fields := []*big.Int{big.NewInt(policy.WithdrawalDomain), ringtest.AsBigInt(p.WithdrawalCount)}
	for _, w := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		fields = append(fields, ringtest.AsBigInt(w.Owner), ringtest.AsBigInt(w.Asset), ringtest.AsBigInt(w.Amount))
	}
	p.WithdrawalHash = spptest.MustHashChain4(t, fields)
	if c := b.Member; c != nil {
		c.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(c.Statement()))
		return
	}
	b.Delegate.PublicInputHash = spptest.MustHashChain4(t, ringtest.ToBigInts(b.Delegate.Statement()))
}

// registry writes every member's record in ascending member order.
func registry(t testing.TB, records map[int64]Record) *ringregistry.Registry {
	t.Helper()
	r := ringregistry.New(t)
	ids := make([]int64, 0, len(records))
	for id := range records {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		record := records[id]
		escrow := big.NewInt(0)
		if record.Registered {
			escrow = ringregistry.EscrowKey(t, nullifierPk(id), ctHash(id))
		}
		lists := new(big.Int).SetUint64(record.Lists)
		r.Apply(t, ringregistry.Entry{Member: big.NewInt(id), Mask: lists, Value: lists, EscrowKey: escrow})
	}
	return r
}

// wires opens the slot under treeID, a dummy keeps the asset and amount no sum counts.
func (s Slot) wires(blinding int64) shared.UtxoWires {
	if s.Owner == 0 && !s.Unowned {
		return shared.UtxoWires{
			Domain: transaction.DummyDomain, TreeID: treeID, OwnerPkHash: 0, NullifierPk: 0, Asset: s.Asset, Amount: s.Amount,
			Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: 0,
		}
	}
	ring := int64(ringID)
	if s.Exit {
		ring = 0
	}
	return shared.UtxoWires{
		Domain: transaction.UtxoDomain, TreeID: treeID, OwnerPkHash: s.Owner, NullifierPk: nullifierPk(s.Owner), Asset: s.Asset,
		Amount: s.Amount, Blinding: blinding, DataHash: 0, RingDataHash: 0, RingProgramID: ring,
	}
}

// utxoHash is the hash private_tx_hash chains for a slot, zero unless the slot is a UTXO.
func utxoHash(t testing.TB, w shared.UtxoWires) *big.Int {
	t.Helper()
	if ringtest.AsBigInt(w.Domain).Int64() != transaction.UtxoDomain {
		return big.NewInt(0)
	}
	utxo := protocol.Utxo{
		Domain:        ringtest.AsBigInt(w.Domain),
		Owner:         spptest.MustOwnerHash(t, ringtest.AsBigInt(w.OwnerPkHash), ringtest.AsBigInt(w.NullifierPk)),
		Asset:         ringtest.AsBigInt(w.Asset),
		Amount:        ringtest.AsBigInt(w.Amount),
		Blinding:      ringtest.AsBigInt(w.Blinding),
		DataHash:      ringtest.AsBigInt(w.DataHash),
		RingDataHash:  ringtest.AsBigInt(w.RingDataHash),
		RingProgramID: ringtest.AsBigInt(w.RingProgramID),
	}
	return spptest.MustUtxoHash(t, utxo, ringtest.AsBigInt(w.TreeID))
}

func pick(slots []Slot, i int) Slot {
	return pad(slots, i, Slot{})
}

func pad[T any](rows []T, i int, zero T) T {
	if i < len(rows) {
		return rows[i]
	}
	return zero
}

func nullifierPk(member int64) *big.Int { return big.NewInt(member + 500_000) }

func ctHash(member int64) *big.Int { return big.NewInt(member + 900_000) }
