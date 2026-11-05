// Proves that a batch of authority writes moved a policy registry from one root to
// the next. The storage program keeps no records, only roots and the next index.
// `Update` hashes the instruction's writes into a chain and verifies the proof over
// that chain, so writes apply in chain order with none skipped or added, and the
// records stay sorted by member, as proofs of a missing record need. Without it a new
// root could drop a block entry or break the order, and a blocked member could prove
// itself unlisted.
//
// Read after registry/registry.go, ringgadget/canonical.go, ringgadget/count.go,
// shared/width.go. Read before registry/tracking.go, policy/record_pool.go,
// prover/ring/ring.go.

package registry

import (
	"errors"
	"math/big"
	"slices"

	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties:
// 1. NewRoot, NewNextIndex and ChainEnd follow from applying, in chain order, exactly the Count writes whose chain runs from ChainStart to ChainEnd.
// 2. A write keeps every list bit outside its mask while the program keeps Value inside Mask.
// 3. A write replaces the mint settings, the withdrawal threshold and the limits together under bit 192 of its MintPolicy, and otherwise keeps them.
// 4. A present member keeps its leaf, its member and its link, a record a write empties stays in the list and reads as empty.
// 5. An absent member is proven absent under the running root and inserted after its low record at exactly the next index below Capacity, and a write that would leave its record empty inserts nothing.
// 6. Every write keeps the links one sorted run from the sentinel to q-1 with every member at a link's end.
// 7. The statement binds both roots, both next indexes, both chain ends and the count.
//
// The program holds what the circuit takes as given. chain_start in program-libs/interface/src/accounts/storage.rs names one registry at one revision in ChainStart, and list_and_mint_entry in program-libs/interface/src/instructions/instruction.rs refuses a member outside [1, q-2], a Value outside its Mask and invalid limits.

// ApplyBatch is the wide apply key's write capacity, mirrored by APPLY_BATCH in program-libs/interface/src/accounts/member_registry.rs.
const ApplyBatch = 16

// ApplyWidths mirrors RingCircuit::apply_records in program-libs/interface/src/proof/key_catalog.rs.
var ApplyWidths = []int{1, 2, 4, 8, ApplyBatch}

// QueueEntry's MintPolicy packs the settings below bit 192 and marks a replacement at bit 192, mirrored by QueueEntry::mint_policy_field in program-libs/interface/src/accounts/member_registry.rs.
type QueueEntry struct {
	Member              frontend.Variable
	Mask                frontend.Variable
	Value               frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
}

// Hash is the entry the program chains at write time in program-libs/interface/src/accounts/member_registry.rs.
func (e QueueEntry) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{shared.QueueWriteDomain, e.Member, e.Mask, e.Value, e.MintPolicy, e.WithdrawalThreshold}, e.AssetLimits[:]))
}

// RecordWrite's Slot opens the member's leaf, or the empty leaf an insert takes.
type RecordWrite struct {
	Entry   QueueEntry
	Exists  frontend.Variable
	Old     RecordBody
	Slot    QuadPath
	Low     Record
	LowSlot QuadPath
}

// ApplyRecordsCircuit keeps the records sorted by member, as proofs of a missing record need.
type ApplyRecordsCircuit struct {
	NumWrites int `gnark:"-"`

	PublicInputHash frontend.Variable `gnark:",public"`

	OldRoot      frontend.Variable
	NewRoot      frontend.Variable
	OldNextIndex frontend.Variable
	NewNextIndex frontend.Variable
	ChainStart   frontend.Variable
	ChainEnd     frontend.Variable
	Count        frontend.Variable
	Writes       []RecordWrite
}

type registryState struct {
	root, next, chain frontend.Variable
}

func NewApplyRecordsCircuit(writes int) (*ApplyRecordsCircuit, error) {
	if err := shared.ValidateWidth("registry", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyRecordsCircuit{NumWrites: writes, Writes: make([]RecordWrite, writes)}, nil
}

func (c *ApplyRecordsCircuit) Define(api frontend.API) error {
	if err := errors.Join(shared.ValidateWidth("registry", c.NumWrites, ApplyWidths), shared.ValidateLength("registry", "write", len(c.Writes), c.NumWrites)); err != nil {
		return err
	}
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	// 2. Every active write moves the running root, next index and chain in instruction order.
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart}
	for i, w := range c.Writes {
		state = w.apply(api, count.Active[i], state)
	}
	// 3. The registry after the batch and the chain end are the statement's.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement()))
	return nil
}

// apply moves s by w while active is set, an unset active leaves it.
func (w RecordWrite) apply(api frontend.API, active frontend.Variable, s registryState) registryState {
	// 1. List bits outside the mask keep their old value, the program keeps the chained Value inside the mask.
	maskBits := api.ToBinary(w.Entry.Mask, ListBits)
	updated := RecordBody{Next: w.Old.Next, Lists: api.Add(keptLists(api, w.Old.Lists, maskBits), w.Entry.Value)}
	// 2. Mint settings move only under bit 192 of the entry, the 193 bit decomposition range-checks it.
	// A separate flag keeps a replacement by all zeros apart from no change.
	policyBits := api.ToBinary(w.Entry.MintPolicy, 193)
	updated.MintPolicy = api.Select(policyBits[192], api.FromBinary(policyBits[:192]...), w.Old.MintPolicy)
	updated.WithdrawalThreshold = api.Select(policyBits[192], w.Entry.WithdrawalThreshold, w.Old.WithdrawalThreshold)
	for i := range updated.AssetLimits {
		updated.AssetLimits[i] = api.Select(policyBits[192], w.Entry.AssetLimits[i], w.Old.AssetLimits[i])
	}
	// 3. An absent member has empty old fields and lies strictly inside its low record's link under the running root, a link no present member falls inside.
	// The argument runs over the tree's whole history. The empty root holds the one link (0, q-1), and an insert splits its link (low, next) into (low, member) and (member, next). The links therefore partition the field with every member at a link's end, a present member falls strictly inside none and AssertOrderedWhen refuses it.
	// The check also runs on a write that inserts nothing. A present member called absent under a write that clears it would otherwise read as empty here, insert nothing and keep its list bit.
	// Empty old fields leave Value and, under bit 192, the entry's mint settings as the new record.
	api.AssertIsBoolean(w.Exists)
	absent := api.Mul(active, api.Sub(1, w.Exists))
	ringgadget.AssertOrderedWhen(api, absent, w.Low.Member, w.Entry.Member, w.Low.Next)
	w.Old.assertEmptyWhen(api, absent)
	relinked := w.Low
	relinked.Next = w.Entry.Member
	lowRoot, relinkedRoot := w.LowSlot.Update(api, w.Low.Hash(api), relinked.Hash(api))
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: absent, A: lowRoot, B: s.root})
	// 4. Only a nonempty new record is inserted, an empty one leaves the member absent.
	var nonzero []frontend.Variable
	for _, field := range updated.contents() {
		nonzero = append(nonzero, ringgadget.IsNonZero(api, field))
	}
	insert := api.Mul(absent, ringgadget.IsAny(api, nonzero...))
	update := api.Mul(active, w.Exists)
	// 5. An insert relinks the low record to the member and takes the empty leaf at the next index, linking on to the low record's old next.
	// The next index keeps one free leaf per insert, a member placed on a later leaf would block the insert that reaches it. At next = Capacity the index fails QuadPath.digits, a full tree takes no member and a write that inserts nothing still passes.
	linked := api.Select(insert, relinkedRoot, s.root)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.Slot.Index, B: s.next})
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: insert, A: w.Old.Next, B: w.Low.Next})
	// 6. An update or insert replaces the slot's old leaf under the running root, an insert's old leaf is the empty leaf 0.
	// On an insert the slot's siblings are those of the tree after the relink, the empty leaf must fold to linked. Exists cannot lie in the other direction either, a member called present must open a leaf that names it.
	before := api.Select(w.Exists, Record{Member: w.Entry.Member, RecordBody: w.Old}.Hash(api), 0)
	after := Record{Member: w.Entry.Member, RecordBody: updated}.Hash(api)
	opened, written := w.Slot.Update(api, before, after)
	changes := api.Add(insert, update)
	abstractor.CallVoid(api, gadget.AssertEqualWhen{Cond: changes, A: opened, B: linked})
	// 7. The chain absorbs every active entry, no write is skipped, added or reordered.
	chain := gadget.PoseidonHash(api, []frontend.Variable{s.chain, w.Entry.Hash(api)})
	return registryState{
		root:  api.Select(changes, written, s.root),
		next:  api.Add(s.next, insert),
		chain: api.Select(active, chain, s.chain),
	}
}

func keptLists(api frontend.API, old frontend.Variable, maskBits []frontend.Variable) frontend.Variable {
	// The bitmap holds ListBits bits, the width of every record and write mask.
	oldBits := api.ToBinary(old, ListBits)
	kept := frontend.Variable(0)
	for i := range oldBits {
		kept = api.Add(kept, api.Mul(oldBits[i], api.Sub(1, maskBits[i]), new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	return kept
}

// statement mirrors ApplyRecordsStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *ApplyRecordsCircuit) statement() []frontend.Variable {
	return []frontend.Variable{
		shared.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count,
	}
}
