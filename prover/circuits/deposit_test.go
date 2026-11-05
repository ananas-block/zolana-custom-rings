package circuits_test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringdeposit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func depositElements(c *circuits.DepositCircuit) int {
	return 4 + 2*circuits.MaxDeposits + 4 + len(c.Credentials.StatementFields()) + 3 + 2*circuits.MaxDeposits
}

const (
	depositDefine = "circuits.(*DepositCircuit).Define"
	outputKey     = "transfer.AssertOutputOwners"
	recordEncode  = "audit.RecordOpening.Encode"
	subjectRead   = "policy.subjectPool.read"
	absentRead    = "policy.recordPool.read"
	treeRoot      = "registry.CredentialLeaf.AssertInclusion"
	depositScreen = "policy.(*Policy).ScreenDeposit"
	paymentRule   = "policy.paymentScreen.assert"
)

func solveDeposit(c *circuits.DepositCircuit) error {
	shape, err := circuits.NewDepositCircuit(c.Capacity)
	if err != nil {
		return err
	}
	return test.IsSolved(shape, c, ecc.BN254.ScalarField())
}

func TestDepositSolvesEachCount(t *testing.T) {
	for _, spec := range []ringdeposit.Spec{
		{Count: 1},
		{Count: 2},
		{Count: circuits.MaxDeposits},
		{Count: 2, ZeroKeys: []int{0, 1}},
		{Count: 3, ZeroKeys: []int{1}},
	} {
		if err := solveDeposit(spec.Build(t).Circuit); err != nil {
			t.Fatalf("%+v: %v", spec, err)
		}
	}
}

func TestDepositSlotRefusals(t *testing.T) {
	tests := []struct {
		name   string
		spec   ringdeposit.Spec
		tamper func(*ringdeposit.Deposit)
		frames []string
	}{
		{"a padding slot with a blinding secret", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.BlindingSecrets[circuits.MaxDeposits-1] = 1
		}, []string{"gadget.AssertZeroWhen", depositDefine}},
		{"a padding slot with an amount", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.Amounts[circuits.MaxDeposits-1] = 1
		}, []string{"gadget.AssertZeroWhen", depositDefine}},
		{"an owner hash of another key on the first slot", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][1] = 0
		}, []string{"gadget.AssertEqualWhen", recordEncode}},
		{"an owner hash of another key on the last slot", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[1][1] = 0
		}, []string{"gadget.AssertEqualWhen", recordEncode}},
		{"owner key bytes outside 0..255 with the same owner identity", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			// Moving 256 between adjacent bytes keeps the identity, the cipher's byte table refuses the encoding.
			key := &d.Circuit.OwnerKeys[0]
			key[3], key[4] = key[3].(int)-1, key[4].(int)+256
		}, []string{"shared.Envelope.SealStream", depositDefine}},
		{"a mint off the slot's asset", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.MintChunks[0][1] = 0
		}, []string{"gadget.AssertEqualWhen", "audit.assertMint"}},
		{"a live amount at 2^64", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.Amounts[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		}, []string{recordEncode}},
		{"a key off the owner's row", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[0] = spptest.MustNullifierPk(t, big.NewInt(0x77))
		}, []string{"gadget.AssertEqualWhen", outputKey}},
		{"a nonzero key with no row", ringdeposit.Spec{Count: 2, ZeroKeys: []int{0}}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[0] = spptest.MustNullifierPk(t, big.NewInt(0x77))
			d.RefillCredentials(t)
		}, []string{"gadget.AssertEqualWhen", outputKey}},
		{"a literal zero key with no row", ringdeposit.Spec{Count: 2, ZeroKeys: []int{0}}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[0] = 0
			d.RefillCredentials(t)
		}, []string{"gadget.AssertZeroWhen", outputKey}},
		{"another credential member with the same state path", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			entry := ringtest.AsBigInt(d.Circuit.OutputEntries[1]).Int64()
			d.Circuit.Openings[entry].Leaf.Member = big.NewInt(0x7712)
		}, []string{"gadget.AssertEqualWhen", treeRoot}},
		{"another owner's row", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.OutputEntries[0] = d.Circuit.OutputEntries[1]
		}, []string{"gadget.AssertEqualWhen", subjectRead}},
		{"another ring's credential root", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.StateRoots = ringregistry.NewCredentials(t, big.NewInt(0x5a0f)).StateRoots(d.Circuit.CredentialPoolSize())
			d.Rebind(t)
		}, []string{"gadget.AssertEqualWhen", treeRoot}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.spec.Build(t)
			tt.tamper(d)
			ringtest.RequireRefused(t, solveDeposit(d.Circuit), tt.frames...)
		})
	}
}

// A blinding off the CRDB domain opens no commitment the circuit rebuilds, the statement names another owner part.
func TestDepositBlindingStaysInTheDepositDomain(t *testing.T) {
	raw := func(_ testing.TB, secret *big.Int) *big.Int { return secret }
	requireStatementRefused(t, ringdeposit.Spec{Count: 2, BlindingOf: raw}.Build(t))
}

// requireStatementRefused holds every slot predicate satisfied and the closing binding alone refused.
func requireStatementRefused(t *testing.T, d *ringdeposit.Deposit) {
	t.Helper()
	err := solveDeposit(d.Circuit)
	ringtest.RequireRefused(t, err, "[assertIsEqual]", depositDefine)
	for _, predicate := range []string{outputKey, subjectRead, absentRead, recordEncode} {
		if strings.Contains(err.Error(), predicate) {
			t.Fatalf("refused at %s, not the statement: %v", predicate, err)
		}
	}
}

// An enrolled owner can receive a zero-key output without a credential query.
func TestDepositZeroKeySurvivesEnrollment(t *testing.T) {
	d := ringdeposit.Spec{Count: 2, ZeroKeys: []int{1}}.Build(t)
	owner := ringtest.AsBigInt(d.Circuit.OwnerPkHashes[1])
	ringpolicy.Enroll(t, d.Credentials, owner, spptest.MustNullifierPk(t, big.NewInt(0x77)))
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
	d.RefillCredentials(t)
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
}

// A salted payee read authenticates absence under the statement address root.
func TestDepositAbsenceReadsTheFrameRoot(t *testing.T) {
	d := ringdeposit.Spec{Count: 2, ZeroKeys: []int{1}, Policy: ringdeposit.SaltedBlock()}.Build(t)
	d.Circuit.AddressRoot = 1
	d.Rebind(t)
	ringtest.RequireRefused(t, solveDeposit(d.Circuit), "gadget.AssertEqualWhen", "registry.AddressGap.AssertAbsent")
}

// A witness off the record's opening refuses inside the encoder merges share.
func TestDepositRecordOffItsOpening(t *testing.T) {
	for name, tamper := range map[string]func(*ringdeposit.Deposit){
		"another owner key": func(d *ringdeposit.Deposit) { d.Circuit.OwnerKeys[0][1] = 0 },
		"another mint":      func(d *ringdeposit.Deposit) { d.Circuit.MintChunks[0][1] = 0 },
		"an amount at 2^64": func(d *ringdeposit.Deposit) { d.Circuit.Amounts[0] = new(big.Int).Lsh(big.NewInt(1), 64) },
	} {
		t.Run(name, func(t *testing.T) {
			d := ringdeposit.Spec{Count: 2}.Build(t)
			tamper(d)
			ringtest.RequireRefused(t, solveDeposit(d.Circuit), "audit.OpeningRecord.Encode")
		})
	}
}

// The frame's bytes differ from the sealed record at one field, the statement over them names bytes the proof never sealed.
func TestEveryDepositRecordFieldIsSealed(t *testing.T) {
	for name, offset := range map[string]int{"kind": 0, "padding": 108, "amount": 8, "owner key": 9, "mint": 41, "nullifier key": 104, "blinding": 143} {
		t.Run(name, func(t *testing.T) {
			d := ringdeposit.Spec{Count: 2}.Build(t)
			d.Plaintext[circuits.DepositRecordLen+offset] ^= 1
			d.Rebind(t)
			requireStatementRefused(t, d)
		})
	}
	t.Run("kind 0 on a live slot", func(t *testing.T) {
		d := ringdeposit.Spec{Count: 2}.Build(t)
		d.Plaintext[0] = audit.KindDummy
		d.Rebind(t)
		requireStatementRefused(t, d)
	})
	t.Run("kind 2 on a live slot", func(t *testing.T) {
		d := ringdeposit.Spec{Count: 2}.Build(t)
		d.Plaintext[0] = audit.KindExit
		d.Rebind(t)
		requireStatementRefused(t, d)
	})
}

// Every element the program computes moves the public input, a witness under the old values refuses at the closing binding.
func TestDepositStatementBindsEveryElement(t *testing.T) {
	d := ringdeposit.Spec{Count: 1}.Build(t)
	d.Narrow(t, 1)
	elements := d.Elements(t)
	if len(elements) != depositElements(d.Circuit) {
		t.Fatalf("%d elements, want %d", len(elements), depositElements(d.Circuit))
	}
	for i := range elements {
		moved := slices.Clone(elements)
		moved[i] = new(big.Int).Add(moved[i], big.NewInt(1))
		d.Circuit.PublicInputHash = spptest.MustHashChain4(t, moved)
		requireStatementRefused(t, d)
	}
}

// The statement length includes the credential table for the selected capacity.
func TestDepositStatementRejectsAnotherHashRound(t *testing.T) {
	for _, capacity := range circuits.DepositCapacities {
		for _, count := range []int{1, capacity} {
			d := ringdeposit.Build(t, count).Narrow(t, capacity)
			elements := d.Elements(t)
			if len(elements) != depositElements(d.Circuit) {
				t.Fatalf("capacity %d count %d holds %d elements", capacity, count, len(elements))
			}
			for _, moved := range [][]*big.Int{
				elements[:len(elements)-4],
				append(slices.Clone(elements), new(big.Int), new(big.Int), new(big.Int), new(big.Int)),
			} {
				d.Circuit.PublicInputHash = spptest.MustHashChain4(t, moved)
				requireStatementRefused(t, d)
			}
		}
	}
}

// The auditor rebuilds every note from its record, the published commitment and asset field accept it, no mint registry or row is read.
func TestDepositReaderRebuildsEachNoteFromItsRecord(t *testing.T) {
	d := ringdeposit.Spec{Count: 3, ZeroKeys: []int{1}}.Build(t)
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
	ciphertext := d.Ciphertext(t)
	for slot, note := range d.Notes {
		opened := d.OpenAt(t, ciphertext, slot)
		if opened.Kind != audit.KindRing {
			t.Fatalf("slot %d reads kind %d", slot, opened.Kind)
		}
		if !opened.Opens(t, note.Commitment(t)) {
			t.Fatalf("slot %d commitment differs", slot)
		}
		if ringtest.AssetField(t, opened.Mint).Cmp(ringtest.AsBigInt(d.Circuit.Assets[slot])) != 0 {
			t.Fatalf("slot %d asset differs", slot)
		}
		if opened.Amount != note.Amount {
			t.Fatalf("slot %d amount %d", slot, opened.Amount)
		}
		zeroKey := opened.NullifierPk.Cmp(shared.ZeroNullifierPk) == 0
		if zeroKey != (slot == 1) {
			t.Fatalf("slot %d reads zero key %v", slot, zeroKey)
		}
	}
	// A record moved to another slot decrypts under that slot's counters to noise.
	moved := slices.Clone(ciphertext)
	copy(moved[circuits.DepositRecordLen:], ciphertext[:circuits.DepositRecordLen])
	for _, note := range d.Notes[:2] {
		if d.OpenAt(t, moved, 1).Opens(t, note.Commitment(t)) {
			t.Fatal("a record read at another slot opened a commitment")
		}
	}
}

// Solved witnesses the Rust statement and record readers reach, a mismatch names a statement the keys refuse.
func TestDepositVectorPinsHostAndCircuit(t *testing.T) {
	type vectorCase struct {
		Name             string   `json:"name"`
		ContextHash      string   `json:"context_hash"`
		Records          []string `json:"records"`
		Ciphertexts      []string `json:"ciphertexts"`
		OwnerUtxoHashes  []string `json:"owner_utxo_hashes"`
		Assets           []string `json:"assets"`
		Amounts          []uint64 `json:"amounts"`
		AuditorPubkey    string   `json:"auditor_pubkey"`
		EphPk            string   `json:"eph_pk"`
		RingID           string   `json:"ring_id"`
		CredentialFields []string `json:"credential_fields"`
		OwnRoot          string   `json:"own_root"`
		CuratorRoot      string   `json:"curator_root"`
		PolicyHash       string   `json:"policy_hash"`
		Elements         []string `json:"elements"`
		PublicInputHash  string   `json:"public_input_hash"`
	}
	cases := make([]vectorCase, 0, 3)
	for _, tc := range []struct {
		name string
		spec ringdeposit.Spec
	}{
		{"confidential", ringdeposit.Spec{Count: 2}},
		{"anonymous_mixed_keys", ringdeposit.Spec{Count: 3, ZeroKeys: []int{1}}},
		{"screened_curator", ringdeposit.Spec{Count: 1, Policy: ringdeposit.CuratorAllowlisted(ringdeposit.MintA)}},
	} {
		d := tc.spec.Build(t)
		if err := solveDeposit(d.Circuit); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		c, ciphertext := d.Circuit, d.Ciphertext(t)
		auditor, eph := d.Keys.AuditorPk(), d.Keys.EphPk()
		tagged := ringprotocol.Tagged(auditor[:])
		v := vectorCase{
			Name: tc.name, ContextHash: ringtest.FieldHex(ringtest.AsBigInt(c.ContextHash)),
			AuditorPubkey: hex.EncodeToString(tagged[:]), EphPk: hex.EncodeToString(eph[:]),
			RingID: ringtest.FieldHex(ringtest.AsBigInt(c.RingProgramID)), OwnRoot: ringtest.FieldHex(ringtest.AsBigInt(c.OwnRoot)), CuratorRoot: ringtest.FieldHex(ringtest.AsBigInt(c.CuratorRoot)), PolicyHash: ringtest.FieldHex(ringtest.AsBigInt(c.PolicyHash)),
			PublicInputHash: ringtest.FieldHex(ringtest.AsBigInt(c.PublicInputHash)),
		}
		for _, field := range c.Credentials.StatementFields() {
			v.CredentialFields = append(v.CredentialFields, ringtest.FieldHex(ringtest.AsBigInt(field)))
		}
		for i, note := range d.Notes {
			start, end := i*circuits.DepositRecordLen, (i+1)*circuits.DepositRecordLen
			v.Records = append(v.Records, hex.EncodeToString(d.Plaintext[start:end]))
			v.Ciphertexts = append(v.Ciphertexts, hex.EncodeToString(ciphertext[start:end]))
			v.OwnerUtxoHashes = append(v.OwnerUtxoHashes, ringtest.FieldHex(note.Commitment(t)))
			v.Assets = append(v.Assets, ringtest.FieldHex(ringtest.AsBigInt(c.Assets[i])))
			v.Amounts = append(v.Amounts, note.Amount)
		}
		for _, element := range d.Elements(t) {
			v.Elements = append(v.Elements, ringtest.FieldHex(element))
		}
		cases = append(cases, v)
	}
	ringProgram := ringregistry.CredentialProgram()
	ringtest.PinVector(t, "deposit/deposit.json", map[string]any{
		"ring_program": hex.EncodeToString(ringProgram[:]),
		"description":  "Solved deposit witnesses. A record is kind || u64be(amount) || owner_key || mint || be32(nullifier_pk) || 7 zero bytes || be32(blinding), slot i at counter 2 + 9 * i under label CRING/dep. owner_utxo_hash = Poseidon(Poseidon(solana_owner_identity(owner_key), nullifier_pk), blinding). Produced by prover/circuits/deposit_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases":        cases,
	})
}

// A policy requiring the allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringdeposit.MintA)).Circuit); err != nil {
		t.Fatalf("listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringdeposit.MintB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), paymentRule, depositScreen)
}

// A curator served allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsCuratorRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringdeposit.MintA)).Circuit); err != nil {
		t.Fatalf("curator listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringdeposit.MintB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), paymentRule, depositScreen)
}

func TestDepositScreensEachRecipientOnTheAllowList(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0, 1)).Circuit); err != nil {
		t.Fatalf("listed recipients refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), paymentRule, depositScreen)
}

func TestDepositScreensEachRecipientOnTheBlockList(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsBlocked()).Circuit); err != nil {
		t.Fatalf("unblocked recipients refused: %v", err)
	}
	blocked := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsBlocked(1)).Circuit
	ringtest.RequireRefused(t, solveDeposit(blocked), paymentRule, depositScreen)
}

func TestDepositScreensEachRecipientOnItsCuratorRecord(t *testing.T) {
	listed := ringdeposit.RecipientsListed(0, 1)
	listed.Curator = true
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, listed).Circuit); err != nil {
		t.Fatalf("curator listed recipients refused: %v", err)
	}
	unlisted := ringdeposit.RecipientsListed(0)
	unlisted.Curator = true
	ringtest.RequireRefused(t, solveDeposit(ringdeposit.BuildScreened(t, 2, unlisted).Circuit), paymentRule, depositScreen)
}

func TestDepositRefusesAnotherRecipientsRecord(t *testing.T) {
	d := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0))
	d.Circuit.OwnerEntries[1] = d.Circuit.OwnerEntries[0]
	ringtest.RequireRefused(t, solveDeposit(d.Circuit), "gadget.AssertEqualWhen", subjectRead)
}

// Eight recipients and SPP's five assets fill the pools, the widest deposit SPP admits.
func TestDepositPoolsHoldTheWidestDeposit(t *testing.T) {
	d := ringdeposit.Spec{Count: circuits.MaxDeposits, Assets: 5, Policy: ringdeposit.RecipientsBlocked()}.Build(t)
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
}

// One recipient of one asset opens one record per subject.
func TestDepositRepeatedSubjectsOpenOneRecord(t *testing.T) {
	d := ringdeposit.Spec{Count: circuits.MaxDeposits, Recipients: 1, Policy: ringdeposit.RecipientsBlocked()}.Build(t)
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
	for slot := range d.Circuit.OwnerEntries {
		if ringtest.AsBigInt(d.Circuit.OwnerEntries[slot].Own).Cmp(ringtest.AsBigInt(d.Circuit.OwnerEntries[0].Own)) != 0 || ringtest.AsBigInt(d.Circuit.AssetEntries[slot].Own).Cmp(ringtest.AsBigInt(d.Circuit.AssetEntries[0].Own)) != 0 {
			t.Fatal("a repeated subject took a second pool entry")
		}
	}
	blocked := ringdeposit.Spec{Count: circuits.MaxDeposits, Recipients: 1, Policy: ringdeposit.RecipientsBlocked(0)}.Build(t)
	ringtest.RequireRefused(t, solveDeposit(blocked.Circuit), paymentRule, depositScreen)
}

// A salted list reads the recipient's salted key, a dictionary of owners finds nothing.
func TestDepositReadsTheSaltedList(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.SaltedBlock()).Circuit); err != nil {
		t.Fatalf("unlisted recipients refused: %v", err)
	}
	blocked := ringdeposit.BuildScreened(t, 2, ringdeposit.SaltedBlock(1))
	ringtest.RequireRefused(t, solveDeposit(blocked.Circuit), paymentRule, depositScreen)
	// A wrong salt misses the blocked record, the credential list tag refuses it.
	forged := ringdeposit.BuildScreened(t, 2, ringdeposit.SaltedBlock(1))
	forged.Circuit.OwnerEntries[1].ListSalt = 7
	ringtest.RequireRefused(t, solveDeposit(forged.Circuit), "gadget.AssertEqualWhen", "policy.(*Policy).resolveSubjects")
	// A zero key recipient has no salt, a deny rule passes.
	zero := ringdeposit.Spec{Count: 2, ZeroKeys: []int{1}, Policy: ringdeposit.SaltedBlock()}.Build(t)
	if err := solveDeposit(zero.Circuit); err != nil {
		t.Fatalf("an unenrolled recipient refused: %v", err)
	}
}

func TestDepositZeroKeyRetainsSaltedPayeeScreening(t *testing.T) {
	for _, blocked := range []bool{false, true} {
		rules := ringdeposit.SaltedBlock()
		if blocked {
			rules = ringdeposit.SaltedBlock(1)
		}
		d := ringdeposit.Spec{Count: 2, Recipients: 1, ZeroKeys: []int{1}, Policy: rules}.Build(t)
		err := solveDeposit(d.Circuit)
		if blocked {
			ringtest.RequireRefused(t, err, paymentRule, depositScreen)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

// The pools mirror DepositSubjects::pool_width in program-libs/interface/src/instructions/deposit.rs.
func TestDepositPoolWidths(t *testing.T) {
	for capacity, width := range map[int]int{1: 2, 2: 4, 4: 8, 8: 21} {
		c := depositCircuit(t, capacity)
		if got := c.RecordPools(); got.Own != width || got.Curator != width {
			t.Fatalf("capacity %d pools %+v, want %d", capacity, got, width)
		}
	}
}

// A salted recipient and an asset fit the next key up, no deposit below four recipients reaches the widest key.
func TestSaltedDepositTakesTheNarrowestKeyItFits(t *testing.T) {
	for _, spec := range []ringdeposit.Spec{
		{Capacity: 2, Count: 1},
		{Capacity: 4, Count: 2},
		{Capacity: 4, Count: 3},
		{Capacity: 8, Count: 4},
	} {
		spec.Policy = ringdeposit.SaltedBlock()
		if err := solveDeposit(spec.Build(t).Circuit); err != nil {
			t.Fatalf("%d recipients on capacity %d: %v", spec.Count, spec.Capacity, err)
		}
	}
	blocked := ringdeposit.Spec{Capacity: 2, Count: 1, Policy: ringdeposit.SaltedBlock(0)}.Build(t)
	ringtest.RequireRefused(t, solveDeposit(blocked.Circuit), paymentRule, depositScreen)
}

// Every slot distinct, each owner's public and salted record, five assets.
func TestDepositPoolsHoldTheSaltedWidestDeposit(t *testing.T) {
	d := ringdeposit.Spec{Count: circuits.MaxDeposits, Assets: 5, Policy: ringdeposit.SaltedBlock()}.Build(t)
	if err := solveDeposit(d.Circuit); err != nil {
		t.Fatal(err)
	}
}

func TestDepositKeys(t *testing.T) {
	for _, capacity := range circuits.DepositCapacities {
		ringkey.RequirePinned(t, fmt.Sprintf("custom_ring_deposit_%d", capacity), ringkey.Compile(t, depositCircuit(t, capacity)))
	}
}

func depositCircuit(t *testing.T, capacity int) *circuits.DepositCircuit {
	t.Helper()
	c, err := circuits.NewDepositCircuit(capacity)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestDepositCapacitiesBindRootTablesAndBoundCounts(t *testing.T) {
	for _, capacity := range circuits.DepositCapacities {
		for _, count := range []int{1, capacity} {
			small := ringdeposit.Build(t, count).Narrow(t, capacity)
			full := ringdeposit.Build(t, count)
			same := ringtest.AsBigInt(small.Circuit.PublicInputHash).Cmp(ringtest.AsBigInt(full.Circuit.PublicInputHash)) == 0
			if same != (capacity == full.Circuit.Capacity) {
				t.Fatal("statement does not bind the credential table capacity")
			}
			if err := solveDeposit(small.Circuit); err != nil {
				t.Fatalf("capacity %d count %d: %v", capacity, count, err)
			}
		}
		for _, count := range []int{0, capacity + 1} {
			bad := ringdeposit.Build(t, 1).Narrow(t, capacity)
			bad.Circuit.Count = count
			if solveDeposit(bad.Circuit) == nil {
				t.Fatalf("capacity %d accepted count %d", capacity, count)
			}
		}
	}
}
