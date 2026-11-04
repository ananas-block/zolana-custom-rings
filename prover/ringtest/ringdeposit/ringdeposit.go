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
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringmerge"
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

// MintA and MintB are the raw addresses the fixtures deposit, the auditor reads them with no mint registry.
var MintA, MintB = fixtureMint(0xa0), fixtureMint(0xb0)

func fixtureMint(seed byte) [32]byte {
	var mint [32]byte
	for i := range mint {
		mint[i] = seed + byte(i)
	}
	return mint
}

// Note is one occupied slot on the host.
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
	// Plaintext is one record per slot of MaxDeposits, the bytes the stream seals.
	Plaintext []byte
}

type Policy struct {
	Rules      []ringpolicy.Rule
	Listed     [][32]byte
	OwnerLists map[int]uint64
	Curator    bool
	// Mint is every slot's deposited token.
	Mint [32]byte
}

// Spec names one deposit, an unset field takes the honest default.
type Spec struct {
	Count int
	Mode  RingMode
	// ZeroKeys holds these slots under ZeroNullifierPk with no row.
	ZeroKeys []int
	Policy   Policy
	// BlindingOf derives the blinding every commitment and record carries.
	BlindingOf func(testing.TB, *big.Int) *big.Int
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

// BuildScreened deposits count owners into a ring whose policy screens every deposit.
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
	own, curator := ringregistry.New(t), ringregistry.New(t)
	c, err := circuits.NewDepositCircuit(circuits.MaxDeposits)
	if err != nil {
		t.Fatal(err)
	}
	d := &Deposit{Circuit: c, Keys: ringaudit.DefaultKeys(t), Tracking: ringregistry.NewTracking(t)}
	c.ContextHash, c.Count, c.Anonymous, c.OwnRoot, c.CuratorRoot = big.NewInt(0xabcdef), s.Count, ringtest.Bit(s.Mode == ModeAnonymous), 0, 0
	c.Table, c.PolicyHash = ringpolicy.Table{}.Wires(), 0
	lists := own
	if s.Policy.Curator {
		lists = curator
	}
	if screened {
		c.Table = ringpolicy.Table{Lists: []uint64{ringregistry.AllowBit, ringregistry.BlockBit}, Curator: map[uint64]bool{ringregistry.AllowBit: s.Policy.Curator, ringregistry.BlockBit: s.Policy.Curator}, Rules: s.Policy.Rules}.Wires()
		c.PolicyHash = ringpolicy.TableHash(t, c.Table)
		for _, mint := range s.Policy.Listed {
			lists.Apply(t, ringregistry.Entry{Member: ringtest.AssetField(t, mint), Mask: big.NewInt(ringregistry.AllowBit), Value: big.NewInt(ringregistry.AllowBit)})
		}
	}
	eph, auditor := d.Keys.EphSk(), d.Keys.AuditorPk()
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	for i := range circuits.MaxDeposits {
		var note Note
		secret := big.NewInt(0)
		c.OwnerPkHashes[i], c.NullifierPks[i], c.Assets[i], c.Amounts[i] = 0, 0, 0, 0
		if i < s.Count {
			secret = big.NewInt(int64(91 + i))
			note = Note{NullifierPk: spptest.MustNullifierPk(t, big.NewInt(int64(51+i))), Blinding: blindingOf(t, secret), Mint: s.Policy.Mint, Amount: uint64(100 + i)}
			for j := range note.OwnerKey {
				note.OwnerKey[j] = byte(i + j + 1)
			}
			ownerPkHash := ringtest.MustSolanaPkField(t, note.OwnerKey)
			if slices.Contains(s.ZeroKeys, i) {
				note.NullifierPk = new(big.Int).Set(shared.ZeroNullifierPk)
			} else {
				ringpolicy.Enroll(t, d.Tracking, ownerPkHash, note.NullifierPk)
			}
			if bits, listed := s.Policy.OwnerLists[i]; listed {
				lists.Apply(t, ringregistry.Entry{Member: ownerPkHash, Mask: new(big.Int).SetUint64(bits), Value: new(big.Int).SetUint64(bits)})
			}
			c.OwnerPkHashes[i], c.NullifierPks[i], c.Assets[i], c.Amounts[i] = ownerPkHash, note.NullifierPk, ringtest.AssetField(t, note.Mint), note.Amount
			d.Notes = append(d.Notes, note)
		}
		c.BlindingSecrets[i] = secret
		ringtest.SetBytes(c.OwnerKeys[i][:], note.OwnerKey[:])
		chunks := protocol.MintChunks(note.Mint)
		c.MintChunks[i] = [2]frontend.Variable{chunks[0], chunks[1]}
		d.Plaintext = append(d.Plaintext, note.plaintext(t)...)
	}
	for i := range circuits.MaxDeposits {
		asset, owner := ringtest.AsBigInt(c.Assets[i]), ringtest.AsBigInt(c.OwnerPkHashes[i])
		c.AssetRecords[i], c.CuratorAssetRecords[i] = own.Opening(asset).Wires(), curator.Opening(asset).Wires()
		c.OwnerRecords[i], c.CuratorOwnerRecords[i] = own.Opening(owner).Wires(), curator.Opening(owner).Wires()
		c.Tracking[i] = ringmerge.UnreadTracking()
		if i < s.Count {
			c.Tracking[i] = d.Tracking.Opening(owner).Wires()
		}
	}
	c.TrackingRoot = d.Tracking.Root()
	if screened {
		c.OwnRoot = own.Root()
	}
	if s.Policy.Curator {
		c.CuratorRoot = curator.Root()
	}
	d.Rebind(t)
	return d
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
	copy(plain[audit.RecordLen:], blinding[:])
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
	chain := []*big.Int{big.NewInt(shared.DepositStatementDomain), ringtest.AsBigInt(c.ContextHash), big.NewInt(int64(len(d.Notes))), ringtest.AsBigInt(c.Anonymous)}
	for i := range circuits.MaxDeposits {
		if i >= len(d.Notes) {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		chain = append(chain, d.Notes[i].Commitment(t), ringtest.HashBytes(t, ciphertext[i*circuits.DepositRecordLen:(i+1)*circuits.DepositRecordLen]))
	}
	chain = append(chain, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, ringtest.AsBigInt(c.TrackingRoot), ringtest.AsBigInt(c.OwnRoot), ringtest.AsBigInt(c.CuratorRoot), ringtest.AsBigInt(c.PolicyHash))
	for i := range circuits.MaxDeposits {
		chain = append(chain, ringtest.AsBigInt(c.Assets[i]), ringtest.AsBigInt(c.Amounts[i]))
	}
	return append(chain, big.NewInt(circuits.DepositStatementVersion))
}

// Rebind rehashes the statement over the host values as set.
func (d *Deposit) Rebind(t testing.TB) {
	t.Helper()
	d.Circuit.PublicInputHash = spptest.MustHashChain(t, d.Elements(t))
}

// Opened is what the auditor reads of one slot.
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
		Amount:      binary.BigEndian.Uint64(plain[8:16]),
		OwnerKey:    [32]byte(plain[16:48]),
		Mint:        [32]byte(plain[48:80]),
		NullifierPk: new(big.Int).SetBytes(plain[80:112]),
		Blinding:    new(big.Int).SetBytes(plain[112:144]),
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

// Narrow keeps the fixed statement while witnessing only the compiled prefix.
func (d *Deposit) Narrow(t testing.TB, capacity int) *Deposit {
	t.Helper()
	c := d.Circuit
	if ringtest.AsBigInt(c.Count).Cmp(big.NewInt(int64(capacity))) > 0 {
		t.Fatal("count exceeds deposit capacity")
	}
	c.Capacity = capacity
	c.OwnerPkHashes = c.OwnerPkHashes[:capacity]
	c.OwnerKeys = c.OwnerKeys[:capacity]
	c.NullifierPks = c.NullifierPks[:capacity]
	c.BlindingSecrets = c.BlindingSecrets[:capacity]
	c.Tracking = c.Tracking[:capacity]
	c.Assets = c.Assets[:capacity]
	c.Amounts = c.Amounts[:capacity]
	c.MintChunks = c.MintChunks[:capacity]
	c.AssetRecords = c.AssetRecords[:capacity]
	c.CuratorAssetRecords = c.CuratorAssetRecords[:capacity]
	c.OwnerRecords = c.OwnerRecords[:capacity]
	c.CuratorOwnerRecords = c.CuratorOwnerRecords[:capacity]
	return d
}
