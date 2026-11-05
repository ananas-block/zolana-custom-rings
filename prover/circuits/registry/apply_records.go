// Proves that a batch of authority writes moved a policy registry from one root to
// the next. The storage program keeps no records, only roots and the next index.
// `Update` hashes the instruction's writes into a chain and verifies the proof over
// that chain, so writes apply in chain order with none skipped or added, and the
// records stay sorted by member, as proofs of a missing record need. Without it a new
// root could drop a block entry or break the order, and a blocked member could prove
// itself unlisted.
//
// One transition serves two key families. A public key compiles the transition alone.
// A private key adds a credential proof per write slot and binds the credential
// checkpoint, and the program selects it only when a write needs one. A public key
// therefore pays no credential constraint, and a private owner write never verifies
// under it because the program refuses that pairing before it reads the proof.
//
// Both families prove whether a batch tightens any field a policy reads. Storage keeps
// the older roots served after a batch that tightens nothing. A proof under an older
// root then reads, per record, values no more permissive than the newest, and every
// rule is monotone in them, so a kept root admits no transfer the newest refuses.
//
// Read after registry/registry.go, ringgadget/canonical.go, ringgadget/count.go,
// shared/width.go, registry/credential_write.go. Read before policy/record_pool.go,
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
// 2. A write keeps every list bit outside its mask and refuses Value bits outside Mask.
// 3. A write replaces the mint settings, the withdrawal threshold and the limits together under bit 192 of its MintPolicy, and otherwise keeps them.
// 4. A present member keeps its leaf, its member and its link, a record a write empties stays in the list and reads as empty.
// 5. An absent member is proven absent under the running root and inserted after its low record at exactly the next index below Capacity, and a write that would leave its record empty inserts nothing.
// 6. Every write keeps the links one sorted run from the sentinel to q-1 with every member at a link's end.
// 7. Under a private key every selected private owner write proves its credential and address under the bound checkpoint.
// 8. The statement binds both roots, both next indexes, both chain ends, the count and the restrictive bit, a private key also the credential bitmap and its root table.
// 9. The restrictive bit is set exactly when an active write clears a grant bit, sets a deny bit, masks a private list, lowers the guard threshold, tightens a cap, cosign or withdrawal bound, or changes an asset limit.
//
// The program holds what the circuit takes as given. RuleTable::validate reads grant lists only by presence and deny lists only by absence. chain_start in program-libs/interface/src/accounts/storage.rs names one registry at one revision in ChainStart, and list_and_mint_entry in program-libs/interface/src/instructions/instruction.rs refuses a member outside [1, q-2], a Value outside its Mask and invalid limits.
// The program derives CredentialWrites from private mask bits after it verifies each asset exemption through Member::asset, and a nonzero bitmap alone selects a private key.
// It derives CredentialOwner from the ring program preimage authenticated by PrivateRingID and raises the checkpoint floor atomically with the root update.

// ApplyBatch is the wide apply key's write capacity, mirrored by APPLY_BATCH in program-libs/interface/src/accounts/member_registry.rs.
const ApplyBatch = 16

// ApplyWidths mirrors RingCircuit::apply_records in program-libs/interface/src/proof/key_catalog.rs.
var ApplyWidths = []int{1, 2, 4, 8, ApplyBatch}

// List bit positions, mirrored by GRANT_LISTS, DENY_LISTS and PRIVATE_LISTS in program-libs/policy/src/list.rs.
var (
	grantListBits   = []int{0, 6, 7}
	denyListBits    = []int{1, 2, 4}
	privateListBits = []int{4, 7}
)

// RecordWrite's MintPolicy packs the settings below bit 192 and marks a replacement at bit 192, mirrored by RecordWrite::mint_policy_field in program-libs/interface/src/accounts/member_registry.rs.
type RecordWrite struct {
	Member              frontend.Variable
	Mask                frontend.Variable
	Value               frontend.Variable
	MintPolicy          frontend.Variable
	WithdrawalThreshold frontend.Variable
	AssetLimits         [LimitFields]frontend.Variable
}

// Hash is the entry the program chains at write time in program-libs/interface/src/accounts/member_registry.rs.
func (e RecordWrite) Hash(api frontend.API) frontend.Variable {
	return gadget.PoseidonHash(api, slices.Concat([]frontend.Variable{shared.RecordWriteDomain, e.Member, e.Mask, e.Value, e.MintPolicy, e.WithdrawalThreshold}, e.AssetLimits[:]))
}

// RecordWriteProofInput's Slot opens the member's leaf, or the empty leaf an insert takes.
type RecordWriteProofInput struct {
	Entry   RecordWrite
	Exists  frontend.Variable
	Old     RecordBody
	Slot    QuadPath
	Low     Record
	LowSlot QuadPath
}

// ApplyRecordsCircuit is the public key, it keeps the records sorted by member, as proofs of a missing record need.
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
	Writes       []RecordWriteProofInput
}

// PrivateApplyRecordsCircuit is the private key, the same transition with one credential slot per write.
type PrivateApplyRecordsCircuit struct {
	ApplyRecordsCircuit

	CredentialWrites frontend.Variable
	PrivateRingID    frontend.Variable
	CredentialOwner  frontend.Variable
	AddressRoot      frontend.Variable
	StateRoots       [][2]frontend.Variable
	Credentials      []CredentialWrite
}

type registryState struct {
	root, next, chain frontend.Variable
	restrictive       frontend.Variable
}

func NewApplyRecordsCircuit(writes int) (*ApplyRecordsCircuit, error) {
	if err := shared.ValidateWidth("registry", writes, ApplyWidths); err != nil {
		return nil, err
	}
	return &ApplyRecordsCircuit{NumWrites: writes, Writes: make([]RecordWriteProofInput, writes)}, nil
}

func NewPrivateApplyRecordsCircuit(writes int) (*PrivateApplyRecordsCircuit, error) {
	core, err := NewApplyRecordsCircuit(writes)
	if err != nil {
		return nil, err
	}
	return &PrivateApplyRecordsCircuit{
		ApplyRecordsCircuit: *core,
		StateRoots:          make([][2]frontend.Variable, writes), Credentials: make([]CredentialWrite, writes),
	}, nil
}

func (c *ApplyRecordsCircuit) Define(api frontend.API) error {
	if err := c.validate(); err != nil {
		return err
	}
	restrictive := c.transition(api, nil)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(restrictive)))
	return nil
}

func (c *PrivateApplyRecordsCircuit) Define(api frontend.API) error {
	if err := errors.Join(
		c.validate(),
		shared.ValidateLength("registry", "state root", len(c.StateRoots), c.NumWrites),
		shared.ValidateLength("registry", "credential", len(c.Credentials), c.NumWrites),
	); err != nil {
		return err
	}
	// 1. The authenticated bitmap selects private owner writes inside the active prefix.
	credentialBits := c.credentialBits(api)
	roots := CredentialRoots{RingID: c.PrivateRingID, Owner: c.CredentialOwner, StateRoots: c.StateRoots}
	// 2. A selected write must carry a private mask, then proves its owner's credential and address.
	// The program derives the bitmap, the circuit only refuses a bit on a write it cannot cover.
	restrictive := c.transition(api, func(i int, active frontend.Variable, maskBits []frontend.Variable) {
		privateMask := anyBit(api, maskBits, privateListBits)
		assertCredentialEqualWhen(api, credentialBits[i], api.Mul(active, privateMask), 1)
		c.Credentials[i].Assert(api, credentialBits[i], c.Writes[i].Entry.Member, c.AddressRoot, roots)
	})
	// 3. The checkpoint and root table extend the public statement.
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.statement(restrictive)))
	return nil
}

func (c *ApplyRecordsCircuit) validate() error {
	return errors.Join(
		shared.ValidateWidth("registry", c.NumWrites, ApplyWidths),
		shared.ValidateLength("registry", "write", len(c.Writes), c.NumWrites),
	)
}

// transition applies the writes in order and returns the restrictive bit, onWrite sees each slot before it applies.
func (c *ApplyRecordsCircuit) transition(api frontend.API, onWrite func(i int, active frontend.Variable, maskBits []frontend.Variable)) frontend.Variable {
	// 1. Count selects a prefix of one write up to the capacity, the writes past it act on nothing.
	count := ringgadget.SelectCount(api, c.Count, 1, c.NumWrites)
	state := registryState{root: c.OldRoot, next: c.OldNextIndex, chain: c.ChainStart, restrictive: 0}
	for i, w := range c.Writes {
		maskBits := api.ToBinary(w.Entry.Mask, ListBits)
		if onWrite != nil {
			onWrite(i, count.Active[i], maskBits)
		}
		// 2. Each authenticated write moves the root and chain in instruction order.
		state = w.apply(api, count.Active[i], state, maskBits)
	}
	// 3. The resulting registry and write chain bind to the statement.
	api.AssertIsEqual(state.root, c.NewRoot)
	api.AssertIsEqual(state.next, c.NewNextIndex)
	api.AssertIsEqual(state.chain, c.ChainEnd)
	return state.restrictive
}

// apply moves s by w while active is set, an unset active leaves it.
func (w RecordWriteProofInput) apply(api frontend.API, active frontend.Variable, s registryState, maskBits []frontend.Variable) registryState {
	// 1. Value contains only masked bits, while every unmasked old bit remains unchanged.
	valueBits := api.ToBinary(w.Entry.Value, ListBits)
	for i, value := range valueBits {
		api.AssertIsEqual(api.Mul(value, api.Sub(1, maskBits[i])), 0)
	}
	oldBits := api.ToBinary(w.Old.Lists, ListBits)
	updated := RecordBody{Next: w.Old.Next, Lists: api.Add(keptLists(api, oldBits, maskBits), w.Entry.Value)}
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
	// 8. An inactive write leaves the restrictive bit, its witness is free.
	restricts := w.restricts(api, listBits{old: oldBits, value: valueBits, mask: maskBits}, policyBits, updated)
	return registryState{
		root:        api.Select(changes, written, s.root),
		next:        api.Add(s.next, insert),
		chain:       api.Select(active, chain, s.chain),
		restrictive: api.Or(s.restrictive, api.Mul(active, restricts)),
	}
}

type listBits struct{ old, value, mask []frontend.Variable }

// restricts compares the stored old record with updated, the old fields read zero for an absent member.
// Every stored amount is a u64 the program encoded, and the sentinel and the empty leaf hold zeros.
func (w RecordWriteProofInput) restricts(api frontend.API, lists listBits, policyBits []frontend.Variable, updated RecordBody) frontend.Variable {
	// 1. A value bit implies its mask bit, a grant bit clears when old, masked and not in value, a deny bit sets when in value and not old.
	// A private mask always restricts.
	tightens := []frontend.Variable{anyBit(api, lists.mask, privateListBits)}
	for _, i := range grantListBits {
		tightens = append(tightens, api.Mul(lists.old[i], lists.mask[i], api.Sub(1, lists.value[i])))
	}
	for _, i := range denyListBits {
		tightens = append(tightens, api.Mul(lists.value[i], api.Sub(1, lists.old[i])))
	}
	// 2. Without bit 192 updated keeps every old amount and no comparison below fires.
	// A guard exempts an amount at most its threshold, a lower threshold exempts less.
	oldPolicy := api.ToBinary(w.Old.MintPolicy, 192)
	updatedLimb := func(k int) (oldLimb, newLimb frontend.Variable) {
		oldLimb = api.FromBinary(oldPolicy[64*k : 64*(k+1)]...)
		return oldLimb, api.Select(policyBits[192], api.FromBinary(policyBits[64*k:64*(k+1)]...), oldLimb)
	}
	oldCosign, newCosign := updatedLimb(0)
	oldCap, newCap := updatedLimb(1)
	oldThreshold, newThreshold := updatedLimb(2)
	tightens = append(tightens,
		lessU64(api, newThreshold, oldThreshold),
		// 3. A zero cap, cosign or withdrawal bound is no bound, so zero orders above every nonzero amount.
		lessU64(api, unboundedTop(api, newCap), unboundedTop(api, oldCap)),
		lessU64(api, unboundedTop(api, newCosign), unboundedTop(api, oldCosign)),
		lessU64(api, unboundedTop(api, updated.WithdrawalThreshold), unboundedTop(api, w.Old.WithdrawalThreshold)),
	)
	// 4. Ring RPC reads the asset limits outside any proof, a window has no permissive order, so any change restricts.
	for i := range updated.AssetLimits {
		tightens = append(tightens, ringgadget.IsNonZero(api, api.Sub(updated.AssetLimits[i], w.Old.AssetLimits[i])))
	}
	return ringgadget.IsAny(api, tightens...)
}

func anyBit(api frontend.API, bits []frontend.Variable, positions []int) frontend.Variable {
	selected := make([]frontend.Variable, len(positions))
	for k, i := range positions {
		selected[k] = bits[i]
	}
	return ringgadget.IsAny(api, selected...)
}

// unboundedTop maps zero to 2^64 - 1 and v to v - 1, both arguments of lessU64 stay below 2^64.
func unboundedTop(api frontend.API, v frontend.Variable) frontend.Variable {
	return api.Sub(api.Add(v, api.Mul(api.IsZero(v), u64Span)), 1)
}

// lessU64 is 1 when a < b, both below 2^64, the 65 bit split of a - b + 2^64 has bit 64 clear exactly then.
func lessU64(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Sub(1, api.ToBinary(api.Add(api.Sub(a, b), u64Span), 65)[64])
}

var u64Span = new(big.Int).Lsh(big.NewInt(1), 64)

func keptLists(api frontend.API, oldBits, maskBits []frontend.Variable) frontend.Variable {
	// The bitmap holds ListBits bits, the width of every record and write mask.
	kept := frontend.Variable(0)
	for i := range oldBits {
		kept = api.Add(kept, api.Mul(oldBits[i], api.Sub(1, maskBits[i]), new(big.Int).Lsh(big.NewInt(1), uint(i))))
	}
	return kept
}

// statement mirrors ApplyRecordsStatement::elements in program-libs/interface/src/proof/statement.rs.
func (c *ApplyRecordsCircuit) statement(restrictive frontend.Variable) []frontend.Variable {
	return []frontend.Variable{
		shared.ApplyRecordsDomain, c.OldRoot, c.NewRoot, c.OldNextIndex, c.NewNextIndex, c.ChainStart, c.ChainEnd, c.Count, restrictive,
	}
}

// statement appends the private section of ApplyRecordsStatement::elements.
func (c *PrivateApplyRecordsCircuit) statement(restrictive frontend.Variable) []frontend.Variable {
	fields := append(c.ApplyRecordsCircuit.statement(restrictive), c.CredentialWrites, c.PrivateRingID, c.CredentialOwner, c.AddressRoot)
	for _, root := range c.StateRoots {
		fields = append(fields, root[:]...)
	}
	return fields
}
