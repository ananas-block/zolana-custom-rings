package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprivatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var (
	confidential2 = transfer.ConfidentialShape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4}
	wideOwners2   = transfer.ConfidentialShape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 24}
	dataKey2      = transfer.ConfidentialShape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4, Data: true}
	confEntry2    = transfer.ConfidentialShape{Inputs: 8, Outputs: 2, Withdrawals: 4, Owners: 4, Entry: true}
	anonymous2    = transfer.AnonymousShape{InputClass: 24, Outputs: 2, Withdrawals: 4, Owners: 4}
	anonData2     = transfer.AnonymousShape{InputClass: 24, Outputs: 2, Withdrawals: 4, Owners: 4, Data: true}
	entry2        = transfer.AnonymousShape{InputClass: 8, Outputs: 2, Withdrawals: 4, Owners: 4, Entry: true}
	coOwner       = big.NewInt(0x0c0c)
	otherOwner    = big.NewInt(0x0d0d)
)

func requireSolved(t *testing.T, circuit frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}

func refused(t *testing.T, circuit frontend.Circuit, frame string) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()), frame)
}

func onRail(shape transfer.ConfidentialShape, rail ringtransfer.Rail) ringtransfer.Confidential {
	w := ringtransfer.Signed(shape)
	w.Rail = rail
	return w
}

func onAnonymous(shape transfer.AnonymousShape, rail ringtransfer.AnonymousRail) ringtransfer.Anonymous {
	w := ringtransfer.Hidden(shape)
	w.Rail = rail
	return w
}

func plain(w ringtransfer.World) ringtransfer.World {
	w.Policy = ringtransfer.Policy{}
	return w
}

func zeroKeyNote(t testing.TB, owner *big.Int, ring *big.Int, amount uint64, blinding int64) ringaudit.Input {
	t.Helper()
	return ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, owner, shared.ZeroNullifierPk, ring, amount, blinding)}
}

func ringID(t testing.TB) *big.Int {
	t.Helper()
	return ringaudit.NewAudit(t, audit.StreamShape{InputClass: 24, Outputs: 2}).RingProgramID
}

func senderNote(t testing.TB, blinding int64) ringaudit.Input {
	t.Helper()
	return ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ringID(t), 100, blinding), OwnerKey: ringtransfer.SenderKey(), Mint: ringaudit.FixtureMint}
}

// Every rail solves its honest witness and binds the public input.
func TestRailsSolve(t *testing.T) {
	inProof := onRail(confidential2, ringtransfer.InProof)
	coOwned := ringtransfer.Signed(confidential2)
	coOwned.CoOwners = []*big.Int{coOwner}
	inProofCoOwned := onRail(confidential2, ringtransfer.InProof)
	inProofCoOwned.CoOwners = []*big.Int{coOwner}
	plainSigner := ringtransfer.Signed(confidential2)
	plainSigner.World = plain(plainSigner.World)
	for name, b := range map[string]func(t *testing.T) frontend.Circuit{
		"signer":                   func(t *testing.T) frontend.Circuit { return ringtransfer.Signed(confidential2).Build(t).Circuit },
		"signer with a co-owner":   func(t *testing.T) frontend.Circuit { return coOwned.Build(t).Circuit },
		"in-proof":                 func(t *testing.T) frontend.Circuit { return inProof.Build(t).Circuit },
		"in-proof beside a signer": func(t *testing.T) frontend.Circuit { return inProofCoOwned.Build(t).Circuit },
		"delegate": func(t *testing.T) frontend.Circuit {
			return onRail(confidential2, ringtransfer.Delegate).Build(t).Circuit
		},
		"plain ring":    func(t *testing.T) frontend.Circuit { return plainSigner.Build(t).Circuit },
		"hidden sender": func(t *testing.T) frontend.Circuit { return ringtransfer.Hidden(anonymous2).Build(t).Circuit },
		"public owners": func(t *testing.T) frontend.Circuit {
			return onAnonymous(anonymous2, ringtransfer.PublicOwners).Build(t).Circuit
		},
		"anonymous delegate": func(t *testing.T) frontend.Circuit {
			return onAnonymous(anonymous2, ringtransfer.AnonymousDelegate).Build(t).Circuit
		},
	} {
		t.Run(name, func(t *testing.T) {
			circuit := b(t)
			ringtest.RequirePublicInputBound(t, circuit, circuit)
		})
	}
}

// Every base shape solves at each owner capacity, a data key's tails included.
func TestEveryKeySolves(t *testing.T) {
	if testing.Short() {
		t.Skip("solves every catalog key")
	}
	for _, shape := range transfer.ConfidentialShapes {
		t.Run(shape.String(), func(t *testing.T) {
			requireSolved(t, ringtransfer.Signed(shape).Build(t).Circuit)
		})
	}
	for _, shape := range transfer.AnonymousShapes {
		t.Run(shape.String(), func(t *testing.T) {
			requireSolved(t, ringtransfer.Hidden(shape).Build(t).Circuit)
		})
	}
	for _, shape := range transfer.EntryShapes {
		t.Run(shape.String(), func(t *testing.T) {
			w := ringtransfer.Hidden(shape)
			w.DefaultInput = shape.InputClass > 2
			requireSolved(t, w.Build(t).Circuit)
		})
	}
	for _, shape := range transfer.ConfidentialEntryShapes {
		t.Run(shape.String(), func(t *testing.T) {
			w := ringtransfer.Signed(shape)
			w.DefaultInput = true
			requireSolved(t, w.Build(t).Circuit)
		})
	}
}

// Every key compiles with one public input and one BSB22 commitment over private wires.
func TestCatalogCompilesToTheVerifiedShape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles the transfer keys")
	}
	compile := func(name string, build func() (frontend.Circuit, error)) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			circuit, err := build()
			if err != nil {
				t.Fatal(err)
			}
			cs := ringkey.Compile(t, circuit)
			t.Logf("%s: %d constraints", name, cs.GetNbConstraints())
			if public := cs.GetNbPublicVariables() - 1; public != 1 {
				t.Errorf("%d public inputs, the program verifies one", public)
			}
		})
	}
	for _, shape := range append(transfer.ConfidentialShapes[:len(transfer.ConfidentialShapes):len(transfer.ConfidentialShapes)], transfer.ConfidentialEntryShapes...) {
		compile(shape.String(), func() (frontend.Circuit, error) { return transfer.NewConfidentialTransferCircuit(shape) })
	}
	for _, shape := range append(transfer.AnonymousShapes[:len(transfer.AnonymousShapes):len(transfer.AnonymousShapes)], transfer.EntryShapes...) {
		compile(shape.String(), func() (frontend.Circuit, error) { return transfer.NewAnonymousTransferCircuit(shape) })
	}
}

// A live input stays under its enrolled key on every rail.
func TestInputPredicateOnEveryRail(t *testing.T) {
	// The witness swaps input 0's key after the world enrolled the honest one.
	wrongKey := spptest.MustNullifierPk(t, big.NewInt(99))
	mutate := func(w ringtransfer.World) ringtransfer.World {
		w.Enrolled = map[string]*big.Int{ringtransfer.Sender(t).String(): wrongKey}
		return w
	}
	unenrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Unenrolled = []*big.Int{ringtransfer.Sender(t)}
		return w
	}
	frame := "transfer.OwnerRows.AssertInputOwners"
	for _, tc := range []struct {
		name  string
		world func(ringtransfer.World) ringtransfer.World
	}{{"a key other than the registered one", mutate}, {"a nonzero key with no row", unenrolled}} {
		t.Run(tc.name, func(t *testing.T) {
			for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
				w := onRail(confidential2, rail)
				w.World = tc.world(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
				w := onAnonymous(anonymous2, rail)
				w.World = tc.world(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			entry := ringtransfer.Signed(confEntry2)
			entry.World = tc.world(entry.World)
			refused(t, entry.Build(t).Circuit, frame)
		})
	}
}

// A zero key reads no row key, the spend path decides who may use it.
func TestZeroKeyInputs(t *testing.T) {
	ring := ringID(t)
	sender := ringtransfer.Sender(t)
	t.Run("a public signer spends it", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("the public owner rail spends it with recipients unpublished", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a hidden sender's own is refused", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		refused(t, w.Build(t).Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
	t.Run("a public co-owner's beside a hidden sender", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner}
		w.Inputs = []ringaudit.Input{senderNote(t, 51), zeroKeyNote(t, coOwner, ring, 100, 52)}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an anonymous delegate moves one in slot 0 with no row", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		b := w.Build(t)
		if ringtest.AsBigInt(b.Circuit.Rows[0]).Sign() != 0 {
			t.Fatal("the delegate's zero key opened a row")
		}
		requireSolved(t, b.Circuit)
	})
	t.Run("a zero key needs a row off the delegate rail", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{zeroKeyNote(t, sender, ring, 200, 51)}
		b := w.Build(t)
		b.Circuit.Rows[0] = 0
		b.Refill(t)
		refused(t, b.Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
}

// The authority rail reads no policy and keeps every auditor check.
func TestDelegateBypass(t *testing.T) {
	frozen := func(w ringtransfer.World) ringtransfer.World {
		w.Policy.Frozen = true
		return w
	}
	t.Run("moves a frozen owner's note", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.World = frozen(w.World)
		requireSolved(t, w.Build(t).Circuit)
		anon := onAnonymous(anonymous2, ringtransfer.AnonymousDelegate)
		anon.World = frozen(anon.World)
		requireSolved(t, anon.Build(t).Circuit)
	})
	t.Run("withdraws with empty legs and pays no threshold", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.Policy.Cap, w.Policy.CosignAbove, w.Policy.WithdrawalThreshold = 1, 1, 1
		w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -500, Gross: 500}}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("exits with the owner published by SPP", func(t *testing.T) {
		shape := transfer.AnonymousShape{InputClass: 16, Outputs: 4, Withdrawals: 4, Owners: 4}
		requireSolved(t, onAnonymous(shape, ringtransfer.AnonymousDelegate).Build(t).Circuit)
	})
	t.Run("several victims move in one transfer", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.CoOwners = []*big.Int{coOwner}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("the statement holds every policy root at zero", func(t *testing.T) {
		for name, set := range map[string]func(*policy.Policy){
			"policy hash":  func(p *policy.Policy) { p.PolicyHash = 7 },
			"own root":     func(p *policy.Policy) { p.OwnRoot = 7 },
			"curator root": func(p *policy.Policy) { p.CuratorRoot = 7 },
		} {
			t.Run(name, func(t *testing.T) {
				b := onRail(confidential2, ringtransfer.Delegate).Build(t)
				set(&b.Circuit.Policy)
				b.Rebind(t)
				refused(t, b.Circuit, "transfer.(*Sections).assertBypass")
			})
		}
	})
	t.Run("a private root", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Circuit.PrivateRoot = 7
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*Sections).assertBypass")
	})
	t.Run("a mask on the authority rail", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.ApprovalMask = policy.ApprovalOutflow
		refused(t, w.Build(t).Circuit, "transfer.(*Sections).prove")
	})
	t.Run("a run on the authority rail", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = []*big.Int{b.Sender}, 1, b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*Sections).prove")
	})
	t.Run("an output still reads its row", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.Delegate)
		w.Unenrolled = []*big.Int{ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 1, 1, 1).OwnerKey)}
		refused(t, w.Build(t).Circuit, "transfer.AssertOutputOwners")
	})
}

// The output predicate binds a live ring output on every rail, an exit keeps its own exception.
func TestOutputPredicateOnEveryRail(t *testing.T) {
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 1, 1, 1).OwnerKey)
	frame := "transfer.AssertOutputOwners"
	unenrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Unenrolled = []*big.Int{recipient}
		return w
	}
	zeroToEnrolled := func(w ringtransfer.World) ringtransfer.World {
		w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) {
			slot.OwnerKey = ringtransfer.SenderKey()
			slot.Utxo.OwnerPkHash, slot.Utxo.NullifierPk = ringtransfer.Sender(t), shared.ZeroNullifierPk
		}}
		return w
	}
	for name, mutate := range map[string]func(ringtransfer.World) ringtransfer.World{"a nonzero key with no row": unenrolled, "a zero key under a row": zeroToEnrolled} {
		t.Run(name, func(t *testing.T) {
			for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
				w := onRail(confidential2, rail)
				w.World = mutate(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
			for _, rail := range []ringtransfer.AnonymousRail{ringtransfer.HiddenSender, ringtransfer.PublicOwners, ringtransfer.AnonymousDelegate} {
				w := onAnonymous(anonymous2, rail)
				w.World = mutate(w.World)
				refused(t, w.Build(t).Circuit, frame)
			}
		})
	}
	t.Run("a zero key to an owner with no row", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Outputs = map[int]func(*ringaudit.Slot){1: func(slot *ringaudit.Slot) { slot.Utxo.NullifierPk = shared.ZeroNullifierPk }}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an exit to an owner with no row", func(t *testing.T) {
		w := ringtransfer.Signed(transfer.ConfidentialShape{Inputs: 24, Outputs: 4, Withdrawals: 4, Owners: 4})
		requireSolved(t, w.Build(t).Circuit)
	})
}

// The program sets the delegate bit and the signer and delegate rails share a key, a signer proof with the bit set is the wall.
func TestDelegateBitIsTheProgramsWall(t *testing.T) {
	circuit, err := transfer.NewConfidentialTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	honest := ringtransfer.Signed(confidential2).Build(t)
	bound := ringkey.Bind(t, circuit, honest.Circuit)
	statement := honest.Statement(t)
	forged := onRail(confidential2, ringtransfer.Delegate).Build(t)
	forged.Circuit.PublicInputHash = spptest.MustHashChain4(t, statement)
	bound.RefuseStatement(t, forged.Circuit, statement)
	// The bit moves the same statement cell the program writes.
	moved := ringtransfer.Signed(confidential2).Build(t)
	moved.Circuit.Delegate, moved.Circuit.SignerCount, moved.Circuit.Signers[0] = 1, 0, 0
	moved.Circuit.PolicyHash, moved.Circuit.OwnRoot, moved.Circuit.CuratorRoot = 0, 0, 0
	moved.Run = nil
	moved.Circuit.PublicInputHash = spptest.MustHashChain4(t, statement)
	if bound.Solve(t, moved.Circuit) == nil {
		t.Fatal("a signer statement admitted the delegate bit")
	}
}

// The public owner rail has no hidden sender, the hidden rail keeps input 0 out of the run.
func TestAnonymousOwnerRails(t *testing.T) {
	t.Run("bits exclude each other", func(t *testing.T) {
		b := onAnonymous(anonymous2, ringtransfer.PublicOwners).Build(t)
		b.Circuit.Delegate = 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*AnonymousTransferCircuit).Define")
	})
	t.Run("a hidden frame with no live input", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.PublicFunded = true
		refused(t, w.Build(t).Circuit, "transfer.(*AnonymousTransferCircuit).hiddenOwner")
	})
	t.Run("public owners spend no input", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		w.PublicFunded = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a hidden sender inside the run", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = []*big.Int{b.Sender}, 1, b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*AnonymousTransferCircuit).hiddenOwner")
	})
	t.Run("a public owner rail input off the run", func(t *testing.T) {
		w := onAnonymous(anonymous2, ringtransfer.PublicOwners)
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = nil, 0, 0
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.SignerSet.AssertOwners")
	})
	for slot := range shared.AnonymousParties {
		t.Run("a hidden sender as a party", func(t *testing.T) {
			b := ringtransfer.Hidden(anonymous2).Build(t)
			b.Circuit.PartyIdentities[slot] = b.Sender
			b.Rebind(t)
			refused(t, b.Circuit, "shared.AssertAnonymousParties")
		})
	}
}

// Every owner opens a row, any rail, up to the key's capacity.
func TestOwnerCapacity(t *testing.T) {
	owners := func(n int) []*big.Int {
		out := make([]*big.Int, n)
		for i := range out {
			out[i] = big.NewInt(0x1000 + int64(i))
		}
		return out
	}
	policied := func(w ringtransfer.World, n int) ringtransfer.World {
		w.CoOwners = owners(n)
		return w
	}
	t.Run("four and twenty four owners, plain and policy", func(t *testing.T) {
		for _, n := range []int{3, 22} {
			shape := confidential2
			if n > 3 {
				shape = wideOwners2
			}
			w := ringtransfer.Signed(shape)
			w.World = policied(w.World, n)
			requireSolved(t, w.Build(t).Circuit)
			w.World = plain(w.World)
			w.World = policied(w.World, n)
			requireSolved(t, w.Build(t).Circuit)
		}
	})
	t.Run("a subject past the key's rows fails closed", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.World = policied(w.World, 4)
		refused(t, w.Build(t).Circuit, "transfer.OwnerRows.AssertInputOwners")
	})
	t.Run("rows out of order", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner, otherOwner}
		b := w.Build(t)
		b.Circuit.Rows[0], b.Circuit.Rows[1] = b.Circuit.Rows[1], b.Circuit.Rows[0]
		b.Refill(t)
		refused(t, b.Circuit, "policy.assertRowsAscending")
	})
	t.Run("a co-owner on a frozen list screens through its row", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners, w.FrozenCoOwner = []*big.Int{coOwner}, true
		refused(t, w.Build(t).Circuit, "policy.assertSenderRules")
	})
	t.Run("a hidden sender and public co-owners", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner, otherOwner, big.NewInt(0x0e0e)}
		requireSolved(t, w.Build(t).Circuit)
	})
}

// An entry key spends default-ring notes beside ring notes under different owners.
func TestEntry(t *testing.T) {
	ring := ringID(t)
	defaultOwnerKey := ringtest.Repeat(0xa2)
	defaultOwner := ringtest.MustSolanaPkField(t, defaultOwnerKey)
	defaultNote := ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, defaultOwner, spptest.MustNullifierPk(t, big.NewInt(8)), big.NewInt(0), 70, 53), OwnerKey: defaultOwnerKey, Mint: ringaudit.FixtureMint}
	ringNote := ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ring, 100, 51), OwnerKey: ringtransfer.SenderKey(), Mint: ringaudit.FixtureMint}
	t.Run("a public default owner beside a hidden ring sender", func(t *testing.T) {
		w := ringtransfer.Hidden(entry2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a confidential rail spends both", func(t *testing.T) {
		w := ringtransfer.Signed(confEntry2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a default owner off the run", func(t *testing.T) {
		w := ringtransfer.Signed(confEntry2)
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		refused(t, w.Build(t).Circuit, "transfer.SignerSet.AssertOwners")
	})
	t.Run("a default note on a key with no entry capacity", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{defaultOwner}
		w.Inputs = []ringaudit.Input{ringNote, defaultNote}
		refused(t, w.Build(t).Circuit, "transfer.InputSection.AssertRingNotes")
	})
	t.Run("a note of another ring on an entry key", func(t *testing.T) {
		other := ringNote
		other.Utxo.RingProgramID = big.NewInt(0x5151)
		w := ringtransfer.Signed(confEntry2)
		w.Inputs = []ringaudit.Input{other}
		refused(t, w.Build(t).Circuit, "transfer.InputSection.AssertRingNotes")
	})
}

// A data output settles on a data key and the records open it.
func TestDataOutputs(t *testing.T) {
	t.Run("a confidential rail", func(t *testing.T) {
		w := ringtransfer.Signed(dataKey2)
		w.HasData = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an anonymous rail", func(t *testing.T) {
		w := ringtransfer.Hidden(anonData2)
		w.HasData = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a data key with the bit clear pays no tails", func(t *testing.T) {
		requireSolved(t, ringtransfer.Signed(dataKey2).Build(t).Circuit)
	})
}

// Dummies stay last and an input past the published count opens nothing.
func TestInputOrder(t *testing.T) {
	sender := ringtransfer.Sender(t)
	nk := ringtransfer.SenderNullifierPk(t)
	ring := ringID(t)
	t.Run("a dummy between spent inputs", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{
			{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)},
			{Utxo: ringaudit.SpareInput(1)},
			{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 60, 52)},
		}
		refused(t, w.Build(t).Circuit, "transfer.OpenInputs")
	})
	t.Run("a note past the published count", func(t *testing.T) {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Audit.InputCount, b.Circuit.InputCount = 1, 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.OpenInputs")
	})
}

// An address slot follows the notes and reaches the proof through the address chain, SPP's rail rules decide who may use it.
func TestAddressSlots(t *testing.T) {
	sender, nk, ring := ringtransfer.Sender(t), ringtransfer.SenderNullifierPk(t), ringID(t)
	addressSlot := func() ringaudit.Input {
		slot := ringaudit.SpareInput(1)
		slot.Domain, slot.OwnerPkHash = transaction.AddressDomain, sender
		return ringaudit.Input{Utxo: slot}
	}
	world := func(t *testing.T) ringtransfer.Confidential {
		w := ringtransfer.Signed(confidential2)
		w.Inputs = []ringaudit.Input{{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)}, addressSlot()}
		return w
	}
	t.Run("beside a spent note", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.AddressChain = 0x77
		b.Rehash(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("the chain binds the transaction hash", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.AddressChain = 0x77
		b.Rehash(t)
		b.Circuit.AddressChain = 0x78
		refused(t, b.Circuit, "transfer.transactionBinding.bindTransaction")
	})
	t.Run("a note called an address leaves the input chain SPP hashed", func(t *testing.T) {
		w := world(t)
		w.Inputs[1] = ringaudit.Input{Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 60, 52)}
		b := w.Build(t)
		spent := b.Circuit.PrivateTxHash
		b.Circuit.Inputs[1].Domain = transaction.AddressDomain
		b.Circuit.PrivateTxHash = spent
		refused(t, b.Circuit, "transfer.transactionBinding.bindTransaction")
	})
	t.Run("a note after an address", func(t *testing.T) {
		w := world(t)
		w.Inputs = []ringaudit.Input{addressSlot(), {Utxo: ringaudit.SpentUtxo(t, sender, nk, ring, 100, 51)}}
		refused(t, w.Build(t).Circuit, "transfer.OpenInputs")
	})
	t.Run("an unknown domain", func(t *testing.T) {
		b := world(t).Build(t)
		b.Circuit.Inputs[1].Domain = 9
		refused(t, b.Circuit, "shared.UtxoWires.OpenInput")
	})
}

// The in-proof rail alone names a public sender.
func TestRailCells(t *testing.T) {
	t.Run("a signer rail sender", func(t *testing.T) {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Circuit.Sender = b.Sender
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*ConfidentialTransferCircuit).assertRail")
	})
	t.Run("a delegate with in_proof", func(t *testing.T) {
		b := onRail(confidential2, ringtransfer.Delegate).Build(t)
		b.Circuit.InProof = 1
		b.Rebind(t)
		refused(t, b.Circuit, "transfer.(*ConfidentialTransferCircuit).assertRail")
	})
	t.Run("an in-proof input of another owner", func(t *testing.T) {
		w := onRail(confidential2, ringtransfer.InProof)
		w.Inputs = []ringaudit.Input{{Utxo: ringaudit.SpentUtxo(t, coOwner, ringtransfer.CoOwnerKey(t, coOwner), ringID(t), 100, 51)}}
		refused(t, w.Build(t).Circuit, "transfer.SignerSet.AssertOwners")
	})
}

// Owner rows read a private source through a salted position, under the tracking row's salt.
func TestPrivateSource(t *testing.T) {
	private := transfer.ConfidentialShape{Inputs: 24, Outputs: 2, Withdrawals: 4, Owners: 4, Private: 10}
	recipient := ringtest.MustSolanaPkField(t, ringaudit.Recipient(t, 0, 0, 1).OwnerKey)
	source := func(t testing.TB, write func(*ringprivatelist.Curator)) *ringtransfer.PrivateSource {
		t.Helper()
		curator := &ringprivatelist.Curator{Tree: ringprivatelist.New(t)}
		if write != nil {
			write(curator)
		}
		return &ringtransfer.PrivateSource{Tree: curator.Tree, OwnerLists: ringregistry.BlockBit, Registry: big.NewInt(0x77)}
	}
	salted := func(t testing.TB, owner *big.Int) *big.Int {
		t.Helper()
		return ringpolicy.ListSaltOf(t, owner)
	}
	blockSalted := func(t testing.TB, owner *big.Int) func(*ringprivatelist.Curator) {
		t.Helper()
		salt := salted(t, owner)
		return func(c *ringprivatelist.Curator) {
			c.WriteSalted(t, owner, salt, ringregistry.ListTag(t, salt), ringregistry.BlockBit, ringregistry.BlockBit)
		}
	}
	world := func(s *ringtransfer.PrivateSource) ringtransfer.Confidential {
		w := ringtransfer.Signed(private)
		w.Private = s
		return w
	}
	t.Run("an owner with no curator action passes through a nonmembership path", func(t *testing.T) {
		requireSolved(t, world(source(t, nil)).Build(t).Circuit)
	})
	t.Run("a privately blocked owner fails the rule", func(t *testing.T) {
		refused(t, world(source(t, blockSalted(t, recipient))).Build(t).Circuit, "policy.assertPaymentRules")
	})
	t.Run("a block written before enrollment stays read at salt zero", func(t *testing.T) {
		s := source(t, func(c *ringprivatelist.Curator) {
			c.WriteUnenrolled(t, recipient, ringregistry.BlockBit, ringregistry.BlockBit)
		})
		refused(t, world(s).Build(t).Circuit, "policy.assertPaymentRules")
	})
	t.Run("an enrolled owner claiming salt zero", func(t *testing.T) {
		b := world(source(t, nil)).Build(t)
		for i, owner := range b.Circuit.PrivateOwners {
			if ringtest.AsBigInt(owner).Cmp(recipient) == 0 {
				b.Circuit.PrivateRows[i].ListSalt = 0
				b.Circuit.PrivateRows[i].Salted = b.World.Private.Tree.Opening(t, recipient, big.NewInt(0))
			}
		}
		refused(t, b.Circuit, "privatelist.Row.read")
	})
	t.Run("an enrolled owner under another salt", func(t *testing.T) {
		b := world(source(t, nil)).Build(t)
		other := big.NewInt(0x1234)
		for i, owner := range b.Circuit.PrivateOwners {
			if ringtest.AsBigInt(owner).Cmp(recipient) == 0 {
				b.Circuit.PrivateRows[i].ListSalt = other
				b.Circuit.PrivateRows[i].Salted = b.World.Private.Tree.Opening(t, recipient, other)
			}
		}
		refused(t, b.Circuit, "privatelist.Row.read")
	})
	t.Run("a stale private root", func(t *testing.T) {
		b := world(source(t, nil)).Build(t)
		b.Circuit.PrivateRoot = 7
		b.Rebind(t)
		refused(t, b.Circuit, "privatelist.Opening.read")
	})
	t.Run("a key with no private rows refuses a source", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.Private = source(t, nil)
		refused(t, w.Build(t).Circuit, "policy.(*Policy).openPrivateRows")
	})
	t.Run("a private key with no source pays for padding rows only", func(t *testing.T) {
		requireSolved(t, ringtransfer.Signed(private).Build(t).Circuit)
	})
	t.Run("a delegate reads no private root", func(t *testing.T) {
		w := onRail(private, ringtransfer.Delegate)
		w.Private = source(t, blockSalted(t, recipient))
		requireSolved(t, w.Build(t).Circuit)
	})
}

// A statement cell moves the public input alone.
func TestStatementBindsEveryElement(t *testing.T) {
	if testing.Short() {
		t.Skip("solves the compiled key once per statement element")
	}
	circuit, err := transfer.NewConfidentialTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	b := ringtransfer.Signed(confidential2).Build(t)
	bound := ringkey.Bind(t, circuit, b.Circuit)
	statement := b.Statement(t)
	for i := range statement {
		moved := append([]*big.Int{}, statement...)
		moved[i] = new(big.Int).Add(moved[i], big.NewInt(1))
		bound.RefuseStatement(t, b.Circuit, moved)
	}
}
