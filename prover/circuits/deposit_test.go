package circuits_test

import (
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
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// 4 head, 8 slots of commitment and ciphertext, 4 keys, 4 roots, 8 slots of asset and amount, the version.
const circuitsDepositElements = 4 + 2*circuits.MaxDeposits + 4 + 4 + 2*circuits.MaxDeposits + 1

const (
	depositDefine = "circuits.(*DepositCircuit).Define"
	outputKey     = "circuits.(*DepositCircuit).assertOutputKey"
	recordEncode  = "audit.RecordOpening.Encode"
	rowResolve    = "registry.TrackingOpening.Resolve"
)

func solveDeposit(c *circuits.DepositCircuit) error {
	shape, err := circuits.NewDepositCircuit(c.Capacity)
	if err != nil {
		return err
	}
	return test.IsSolved(shape, c, ecc.BN254.ScalarField())
}

func TestDepositSolvesEachCountAndMode(t *testing.T) {
	for _, spec := range []ringdeposit.Spec{
		{Count: 1},
		{Count: circuits.MaxDeposits},
		{Count: 2, Mode: ringdeposit.ModeAnonymous},
		{Count: 2, ZeroKeys: []int{0, 1}},
		{Count: 3, Mode: ringdeposit.ModeAnonymous, ZeroKeys: []int{1}},
	} {
		if err := solveDeposit(spec.Build(t).Circuit); err != nil {
			t.Fatalf("%+v: %v", spec, err)
		}
	}
}

// Each case changes one value of an honest deposit and names the check that refuses it.
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
		{"an anonymous owner hash of another key", ringdeposit.Spec{Count: 2, Mode: ringdeposit.ModeAnonymous}, func(d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[0][1] = 0
		}, []string{"gadget.AssertEqualWhen", recordEncode}},
		{"a confidential owner hash of another key", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.OwnerKeys[1][1] = 0
		}, []string{"gadget.AssertEqualWhen", recordEncode}},
		{"owner key bytes outside 0..255 with the same owner identity", ringdeposit.Spec{Count: 2, Mode: ringdeposit.ModeAnonymous}, func(d *ringdeposit.Deposit) {
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
		}, []string{"[assertIsEqual]", outputKey}},
		{"a nonzero key with no row", ringdeposit.Spec{Count: 2, ZeroKeys: []int{0}}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[0] = spptest.MustNullifierPk(t, big.NewInt(0x77))
		}, []string{"[assertIsEqual]", outputKey}},
		{"a zero key on an enrolled owner", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[1] = new(big.Int).Set(shared.ZeroNullifierPk)
		}, []string{"[assertIsEqual]", outputKey}},
		{"a zero key claiming absence over the owner's own leaf", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.NullifierPks[1] = new(big.Int).Set(shared.ZeroNullifierPk)
			d.Circuit.Tracking[1].Present = 0
		}, []string{"ringgadget.AssertOrderedWhen", rowResolve}},
		{"another owner's row", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.Tracking[0] = d.Circuit.Tracking[1]
		}, []string{"gadget.AssertEqualWhen", rowResolve}},
		{"a tracking flag off 0 and 1", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.Tracking[0].Present = 2
		}, []string{"[assertIsBoolean]", rowResolve}},
		{"another ring's tracking root", ringdeposit.Spec{Count: 2}, func(d *ringdeposit.Deposit) {
			d.Circuit.TrackingRoot = ringregistry.NewTracking(t).Root()
			d.Rebind(t)
		}, []string{"gadget.AssertEqualWhen", rowResolve}},
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
	for _, predicate := range []string{outputKey, rowResolve, recordEncode} {
		if strings.Contains(err.Error(), predicate) {
			t.Fatalf("refused at %s, not the statement: %v", predicate, err)
		}
	}
}

// A sender names zero for a wallet that enrolled after the frame's root, the window the output rule accepts.
func TestDepositZeroKeyHoldsAtTheRootTheFrameNames(t *testing.T) {
	spec := ringdeposit.Spec{Count: 2, ZeroKeys: []int{1}}
	stale := spec.Build(t)
	owner := ringtest.AsBigInt(stale.Circuit.OwnerPkHashes[1])
	ringpolicy.Enroll(t, stale.Tracking, owner, spptest.MustNullifierPk(t, big.NewInt(0x77)))
	if err := solveDeposit(stale.Circuit); err != nil {
		t.Fatalf("a zero key under the root before enrollment: %v", err)
	}
	// The row is present under the current root and no opening of it reads absent.
	current := stale.Tracking.Opening(owner).Wires()
	stale.Circuit.TrackingRoot, stale.Circuit.Tracking[1] = stale.Tracking.Root(), current
	stale.Circuit.Tracking[0] = stale.Tracking.Opening(ringtest.AsBigInt(stale.Circuit.OwnerPkHashes[0])).Wires()
	stale.Rebind(t)
	ringtest.RequireRefused(t, solveDeposit(stale.Circuit), "[assertIsEqual]", outputKey)
}

// A low record of the tree before enrollment proves no absence under the root after it.
func TestDepositAbsenceReadsTheFrameRoot(t *testing.T) {
	d := ringdeposit.Spec{Count: 2, ZeroKeys: []int{1}}.Build(t)
	owner := ringtest.AsBigInt(d.Circuit.OwnerPkHashes[1])
	ringpolicy.Enroll(t, d.Tracking, owner, spptest.MustNullifierPk(t, big.NewInt(0x77)))
	d.Circuit.TrackingRoot = d.Tracking.Root()
	d.Circuit.Tracking[0] = d.Tracking.Opening(ringtest.AsBigInt(d.Circuit.OwnerPkHashes[0])).Wires()
	d.Rebind(t)
	ringtest.RequireRefused(t, solveDeposit(d.Circuit), "gadget.AssertEqualWhen", rowResolve)
}

// The frame's bytes differ from the sealed record at one field, the statement over them names bytes the proof never sealed.
func TestEveryDepositRecordFieldIsSealed(t *testing.T) {
	for name, offset := range map[string]int{"kind": 0, "reserved": 3, "amount": 15, "owner key": 16, "mint": 48, "nullifier key": 111, "blinding": 143} {
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
	elements := d.Elements(t)
	d.Narrow(t, 1)
	if len(elements) != circuitsDepositElements {
		t.Fatalf("%d elements, want %d", len(elements), circuitsDepositElements)
	}
	for i := range elements {
		moved := slices.Clone(elements)
		moved[i] = new(big.Int).Add(moved[i], big.NewInt(1))
		d.Circuit.PublicInputHash = spptest.MustHashChain(t, moved)
		requireStatementRefused(t, d)
	}
	if last := elements[len(elements)-1]; last.Cmp(big.NewInt(circuits.DepositStatementVersion)) != 0 {
		t.Fatalf("the statement closes on %v", last)
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
		if opened.Commitment(t).Cmp(note.Commitment(t)) != 0 {
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
	if d.OpenAt(t, moved, 1).Commitment(t).Cmp(d.Notes[1].Commitment(t)) == 0 {
		t.Fatal("a record read at another slot opened its commitment")
	}
}

// A policy requiring the allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringdeposit.MintA)).Circuit); err != nil {
		t.Fatalf("listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.Allowlisted(ringdeposit.MintB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), "policy.paymentScreen.assert", "policy.DepositScreen.Assert")
}

// A curator served allow list admits a listed asset and refuses one off it.
func TestDepositScreensEachAssetOnItsCuratorRecord(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringdeposit.MintA)).Circuit); err != nil {
		t.Fatalf("curator listed asset refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.CuratorAllowlisted(ringdeposit.MintB)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), "policy.paymentScreen.assert", "policy.DepositScreen.Assert")
}

func TestDepositScreensEachRecipientOnTheAllowList(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0, 1)).Circuit); err != nil {
		t.Fatalf("listed recipients refused: %v", err)
	}
	unlisted := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0)).Circuit
	ringtest.RequireRefused(t, solveDeposit(unlisted), "policy.paymentScreen.assert", "policy.DepositScreen.Assert")
}

func TestDepositScreensEachRecipientOnTheBlockList(t *testing.T) {
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsBlocked()).Circuit); err != nil {
		t.Fatalf("unblocked recipients refused: %v", err)
	}
	blocked := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsBlocked(1)).Circuit
	ringtest.RequireRefused(t, solveDeposit(blocked), "policy.paymentScreen.assert", "policy.DepositScreen.Assert")
}

func TestDepositScreensEachRecipientOnItsCuratorRecord(t *testing.T) {
	listed := ringdeposit.RecipientsListed(0, 1)
	listed.Curator = true
	if err := solveDeposit(ringdeposit.BuildScreened(t, 2, listed).Circuit); err != nil {
		t.Fatalf("curator listed recipients refused: %v", err)
	}
	unlisted := ringdeposit.RecipientsListed(0)
	unlisted.Curator = true
	ringtest.RequireRefused(t, solveDeposit(ringdeposit.BuildScreened(t, 2, unlisted).Circuit), "policy.paymentScreen.assert", "policy.DepositScreen.Assert")
}

func TestDepositRefusesAnotherRecipientsRecord(t *testing.T) {
	d := ringdeposit.BuildScreened(t, 2, ringdeposit.RecipientsListed(0))
	d.Circuit.OwnerRecords[1] = d.Circuit.OwnerRecords[0]
	ringtest.RequireRefused(t, solveDeposit(d.Circuit), "policy.DepositScreen.Assert")
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

func TestDepositCapacitiesPreserveStatementsAndBoundCounts(t *testing.T) {
	for _, capacity := range circuits.DepositCapacities {
		for _, count := range []int{1, capacity} {
			for _, mode := range []ringdeposit.RingMode{ringdeposit.ModeConfidential, ringdeposit.ModeAnonymous} {
				small := ringdeposit.Build(t, count, mode).Narrow(t, capacity)
				full := ringdeposit.Build(t, count, mode)
				if ringtest.AsBigInt(small.Circuit.PublicInputHash).Cmp(ringtest.AsBigInt(full.Circuit.PublicInputHash)) != 0 {
					t.Fatal("capacity changed deposit statement")
				}
				if err := solveDeposit(small.Circuit); err != nil {
					t.Fatalf("capacity %d count %d: %v", capacity, count, err)
				}
			}
		}
		for _, count := range []int{0, capacity + 1} {
			bad := ringdeposit.Build(t, 1, ringdeposit.ModeConfidential).Narrow(t, capacity)
			bad.Circuit.Count = count
			if solveDeposit(bad.Circuit) == nil {
				t.Fatalf("capacity %d accepted count %d", capacity, count)
			}
		}
	}
}
