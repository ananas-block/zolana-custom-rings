// Package ringdeposit is the host twin of the ring deposit circuit for the Go tests.
package ringdeposit

import (
	"encoding/binary"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// RingMode mirrors RingMode in program-libs/interface/src/accounts/state.rs, the flag DepositPublicInput binds follows it.
type RingMode int

const (
	ModeConfidential RingMode = iota
	ModeAnonymous
)

var MintA, MintB = fixtureMint(0xa0), fixtureMint(0xb0)

func fixtureMint(seed byte) [32]byte {
	var mint [32]byte
	for i := range mint {
		mint[i] = seed + byte(i)
	}
	return mint
}

type Note struct {
	OwnerKey    [32]byte
	NullifierPk *big.Int
	Blinding    *big.Int
	Mint        [32]byte
	Amount      uint64
}

type Deposit struct {
	Circuit  *circuits.DepositCircuit
	Keys     ringaudit.Keys
	Notes    []Note
	Tracking *ringregistry.Tracking
	spec     Spec
	// Plaintext is one record per slot of MaxDeposits, the bytes the stream seals.
	Plaintext []byte
}

type Policy struct {
	Rules      []ringpolicy.Rule
	Listed     [][32]byte
	OwnerLists map[int]uint64
	Curator    bool
	Mint       [32]byte
	// SaltedBlocked slots sit on PrivateBlockBit at their salted keys.
	SaltedBlocked []int
	Salted        bool
}

// Spec names one deposit, an unset field takes the honest default.
type Spec struct {
	// Capacity is the key's slots, zero takes MaxDeposits.
	Capacity int
	Count    int
	Mode     RingMode
	// ZeroKeys holds these slots under ZeroNullifierPk with no row.
	ZeroKeys []int
	// Recipients cycles this many owners over the slots and Assets this many mints, zero gives each slot its own owner and every slot Policy.Mint.
	Recipients, Assets int
	Policy             Policy
	BlindingOf         func(testing.TB, *big.Int) *big.Int
}

// Build deposits count enrolled owners under the CRDB blinding.
func Build(t testing.TB, count int, mode RingMode) *Deposit {
	t.Helper()
	return Spec{Count: count, Mode: mode}.Build(t)
}

// Allowlisted requires every deposited asset on AllowBit, where the registry lists only MintA.
func Allowlisted(mint [32]byte) Policy {
	return Policy{Rules: []ringpolicy.Rule{ringpolicy.Require(policy.SubjectAsset, ringregistry.AllowBit)}, Listed: [][32]byte{MintA}, Mint: mint}
}

// CuratorAllowlisted is Allowlisted with AllowBit served by the curator registry.
func CuratorAllowlisted(mint [32]byte) Policy {
	listed := Allowlisted(mint)
	listed.Curator = true
	return listed
}

func RecipientsListed(slots ...int) Policy {
	lists := make(map[int]uint64, len(slots))
	for _, slot := range slots {
		lists[slot] = ringregistry.AllowBit
	}
	return Policy{Rules: []ringpolicy.Rule{ringpolicy.Require(policy.SubjectOutputOwner, ringregistry.AllowBit)}, OwnerLists: lists, Mint: MintA}
}

func RecipientsBlocked(slots ...int) Policy {
	lists := make(map[int]uint64, len(slots))
	for _, slot := range slots {
		lists[slot] = ringregistry.BlockBit
	}
	return Policy{Rules: []ringpolicy.Rule{ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.BlockBit)}, OwnerLists: lists, Mint: MintA}
}

// SaltedBlock forbids PrivateBlockBit read at each recipient's salted key.
func SaltedBlock(slots ...int) Policy {
	return Policy{Rules: []ringpolicy.Rule{ringpolicy.Forbid(policy.SubjectOutputOwner, ringregistry.PrivateBlockBit)}, Mint: MintA, Salted: true, SaltedBlocked: slots}
}

func BuildScreened(t testing.TB, count int, policy Policy) *Deposit {
	t.Helper()
	return Spec{Count: count, Policy: policy}.Build(t)
}

func (s Spec) Build(t testing.TB) *Deposit {
	t.Helper()
	blindingOf := s.BlindingOf
	if blindingOf == nil {
		blindingOf = ringprotocol.DepositBlinding
	}
	screened := s.Policy.Rules != nil
	if s.Policy.Mint == ([32]byte{}) {
		s.Policy.Mint = MintA
	}
	capacity := s.Capacity
	if capacity == 0 {
		capacity = circuits.MaxDeposits
	}
	own, curator := ringregistry.New(t), ringregistry.New(t)
	c, err := circuits.NewDepositCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	d := &Deposit{Circuit: c, Keys: ringaudit.DefaultKeys(t), Tracking: ringregistry.NewTracking(t), spec: s}
	c.ContextHash, c.Count = big.NewInt(0xabcdef), s.Count
	zeroUnreadInputs(&c.Policy)
	c.Table, c.PolicyHash = ringpolicy.Table{}.Wires(), 0
	lists := own
	if s.Policy.Curator {
		lists = curator
	}
	if screened {
		salted := uint64(0)
		if s.Policy.Salted {
			salted = ringregistry.PrivateBlockBit
		}
		c.Table = ringpolicy.Table{Lists: []uint64{ringregistry.AllowBit, ringregistry.BlockBit, ringregistry.PrivateBlockBit}, Curator: map[uint64]bool{ringregistry.AllowBit: s.Policy.Curator, ringregistry.BlockBit: s.Policy.Curator, ringregistry.PrivateBlockBit: s.Policy.Curator}, Rules: s.Policy.Rules, Salted: salted}.Wires()
		c.PolicyHash = ringpolicy.TableHash(t, c.Table)
		for _, mint := range s.Policy.Listed {
			lists.Apply(t, ringregistry.Entry{Member: ringtest.AssetField(t, mint), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(ringregistry.AllowBit)})
		}
	}
	eph, auditor := d.Keys.EphSk(), d.Keys.AuditorPk()
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	outputs := make([]shared.UtxoWires, capacity)
	owners := make([]frontend.Variable, capacity)
	for i := range circuits.MaxDeposits {
		var note Note
		secret, ownerPkHash, asset := big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < s.Count {
			secret = big.NewInt(int64(91 + i))
			recipient := i
			if s.Recipients > 0 {
				recipient = i % s.Recipients
			}
			mint := s.Policy.Mint
			if s.Assets > 0 {
				mint = fixtureMint(0xa0 + byte(i%s.Assets))
			}
			note = Note{NullifierPk: spptest.MustNullifierPk(t, big.NewInt(int64(51+recipient))), Blinding: blindingOf(t, secret), Mint: mint, Amount: uint64(100 + i)}
			for j := range note.OwnerKey {
				note.OwnerKey[j] = byte(recipient + j + 1)
			}
			ownerPkHash, asset = ringtest.MustSolanaPkField(t, note.OwnerKey), ringtest.AssetField(t, note.Mint)
			if slices.Contains(s.ZeroKeys, i) {
				note.NullifierPk = new(big.Int).Set(shared.ZeroNullifierPk)
			} else if !d.Tracking.Opening(ownerPkHash).Present {
				ringpolicy.Enroll(t, d.Tracking, ownerPkHash, note.NullifierPk)
			}
			if slices.Contains(s.Policy.SaltedBlocked, i) {
				lists.Apply(t, ringregistry.Entry{Member: ringregistry.ListKey(t, ownerPkHash, ringpolicy.ListSaltOf(t, ownerPkHash)), Mask: big.NewInt(ringregistry.PrivateBlockBit), Value: big.NewInt(ringregistry.PrivateBlockBit)})
			}
			if bits, listed := s.Policy.OwnerLists[i]; listed {
				lists.Apply(t, ringregistry.Entry{Member: ownerPkHash, Mask: new(big.Int).SetUint64(bits), Value: new(big.Int).SetUint64(bits)})
			}
			d.Notes = append(d.Notes, note)
		}
		d.Plaintext = append(d.Plaintext, note.plaintext(t)...)
		if i >= capacity {
			continue
		}
		c.OwnerPkHashes[i], c.NullifierPks[i], c.Assets[i], c.Amounts[i], c.BlindingSecrets[i] = ownerPkHash, big.NewInt(0), asset, note.Amount, secret
		if note.NullifierPk != nil {
			c.NullifierPks[i] = note.NullifierPk
		}
		ringtest.SetBytes(c.OwnerKeys[i][:], note.OwnerKey[:])
		chunks := protocol.MintChunks(note.Mint)
		c.MintChunks[i] = [2]frontend.Variable{chunks[0], chunks[1]}
		owners[i] = ownerPkHash
		outputs[i] = shared.UtxoWires{Domain: big.NewInt(0), OwnerPkHash: ownerPkHash, Asset: asset}
		if i < s.Count {
			outputs[i].Domain = big.NewInt(protocol.UtxoDomain)
		}
	}
	ringpolicy.FillPools(t, &c.Policy, outputs, nil, nil, own, curator, d.Tracking)
	ringpolicy.FillTracking(t, &c.Tracking, d.Tracking, nil, owners, &c.Policy, owners)
	c.OwnRoot, c.CuratorRoot = big.NewInt(0), big.NewInt(0)
	if screened {
		c.OwnRoot = own.Root()
	}
	if s.Policy.Curator {
		c.CuratorRoot = curator.Root()
	}
	d.Rebind(t)
	return d
}

// zeroUnreadInputs assigns the wires a deposit shares with a transfer and never reads.
func zeroUnreadInputs(p *policy.Policy) {
	p.WithdrawalCount, p.WithdrawalHash, p.RingProgramID = 0, 0, 0
	for k := range p.PublicAssets {
		p.PublicAssets[k], p.PublicAmounts[k], p.PublicGross[k] = 0, 0, 0
	}
}

// plaintext mirrors OpeningRecord::encode, all zero on a padding slot.
func (n Note) plaintext(t testing.TB) []byte {
	t.Helper()
	plain := make([]byte, circuits.DepositRecordLen)
	if n.NullifierPk == nil {
		return plain
	}
	record := ringaudit.Slot{Utxo: ringaudit.Utxo{Domain: protocol.UtxoDomain, NullifierPk: n.NullifierPk, Amount: n.Amount, RingProgramID: big.NewInt(1)}, OwnerKey: n.OwnerKey, Mint: n.Mint}.Record(t)
	blinding := spptest.MustFieldBytes(t, n.Blinding)
	copy(plain, record)
	copy(plain[audit.RecordStride:], blinding[:])
	return plain
}

// Commitment is the owner part SPP receives, Poseidon(Poseidon(owner_pk_hash, nullifier_pk), blinding).
func (n Note) Commitment(t testing.TB) *big.Int {
	t.Helper()
	return ringtest.MustPoseidonHash(t, spptest.MustOwnerHash(t, ringtest.MustSolanaPkField(t, n.OwnerKey), n.NullifierPk), n.Blinding)
}

// Ciphertext is the sealed stream, a slot's record at i * DepositRecordLen.
func (d *Deposit) Ciphertext(t testing.TB) []byte {
	t.Helper()
	return d.Keys.StreamCiphertext(t, d.Plaintext, shared.DepositEncInfo)
}

// Elements mirrors DepositPublicInput::elements over the host values as set.
func (d *Deposit) Elements(t testing.TB) []*big.Int {
	t.Helper()
	c, ciphertext := d.Circuit, d.Ciphertext(t)
	sealed := d.Keys.Sealed(t, ciphertext)
	chain := []*big.Int{big.NewInt(shared.DepositStatementDomain), ringtest.AsBigInt(c.ContextHash), big.NewInt(int64(len(d.Notes)))}
	for i := range circuits.MaxDeposits {
		if i >= len(d.Notes) {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		chain = append(chain, d.Notes[i].Commitment(t), ringtest.HashBytes(t, ciphertext[i*circuits.DepositRecordLen:(i+1)*circuits.DepositRecordLen]))
	}
	chain = append(chain, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, ringtest.AsBigInt(c.TrackingRoot), ringtest.AsBigInt(c.OwnRoot), ringtest.AsBigInt(c.CuratorRoot), ringtest.AsBigInt(c.PolicyHash))
	for i := range circuits.MaxDeposits {
		if i >= c.Capacity {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		chain = append(chain, ringtest.AsBigInt(c.Assets[i]), ringtest.AsBigInt(c.Amounts[i]))
	}
	return chain
}

// RefillTracking opens every owner under the tree's current root and rebinds.
func (d *Deposit) RefillTracking(t testing.TB) {
	t.Helper()
	ringpolicy.FillTracking(t, &d.Circuit.Tracking, d.Tracking, nil, d.Circuit.OwnerPkHashes, &d.Circuit.Policy, d.Circuit.OwnerPkHashes)
	d.Rebind(t)
}

func (d *Deposit) Rebind(t testing.TB) {
	t.Helper()
	d.Circuit.PublicInputHash = spptest.MustHashChain4(t, d.Elements(t))
}

type Opened struct {
	Kind        byte
	Amount      uint64
	OwnerKey    [32]byte
	Mint        [32]byte
	NullifierPk *big.Int
	Blinding    *big.Int
}

// OpenAt reverses the stream at slot, CTR is its own inverse and a record read at another slot's counters is noise.
func (d *Deposit) OpenAt(t testing.TB, ciphertext []byte, slot int) Opened {
	t.Helper()
	plain := d.Keys.StreamCiphertext(t, ciphertext, shared.DepositEncInfo)[slot*circuits.DepositRecordLen:]
	return Opened{
		Kind:        plain[0],
		Amount:      binary.BigEndian.Uint64(plain[1:9]),
		OwnerKey:    [32]byte(plain[9:41]),
		Mint:        [32]byte(plain[41:73]),
		NullifierPk: new(big.Int).SetBytes(plain[73:audit.RecordLen]),
		Blinding:    new(big.Int).SetBytes(plain[audit.RecordStride:circuits.DepositRecordLen]),
	}
}

// Opens rebuilds the published owner part from the record alone, a value at or above q is no field element the proof sealed.
func (o Opened) Opens(t testing.TB, commitment *big.Int) bool {
	t.Helper()
	q := ecc.BN254.ScalarField()
	if o.NullifierPk.Cmp(q) >= 0 || o.Blinding.Cmp(q) >= 0 {
		return false
	}
	return Note{OwnerKey: o.OwnerKey, NullifierPk: o.NullifierPk, Blinding: o.Blinding}.Commitment(t).Cmp(commitment) == 0
}

// Narrow rebuilds the deposit on a narrower key, whose pools hold the fixed statement's values.
func (d *Deposit) Narrow(t testing.TB, capacity int) *Deposit {
	t.Helper()
	if d.spec.Count > capacity {
		t.Fatal("count exceeds deposit capacity")
	}
	spec := d.spec
	spec.Capacity = capacity
	*d = *spec.Build(t)
	return d
}
