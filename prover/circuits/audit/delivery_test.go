package audit_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

const (
	deliverRecipients = "audit.AuditWires.DeliverRecipients"
	recipientBody     = "audit.AuditWires.assertRecipientBody"
)

// deliveryShape holds change in slot 0, payments in slots 1 and 3 and an exit in slot 2.
var deliveryShape = audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}

func requireFrame(t *testing.T, a ringaudit.AnonymousAudit, frame string) {
	t.Helper()
	assignment := a.Circuit(t)
	ringtest.RequireRefused(t, test.IsSolved(ringaudit.NewAnonymousCircuit(a.Shape), assignment, ecc.BN254.ScalarField()), frame)
}

// A record names one address, each slot opens the owner's exact keys under the statement's ring.
func TestSlotAddressBindsEveryKey(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, deliveryShape).Circuit(t))
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		// The body would decrypt for the right holder while the note stays unspendable under the bound key.
		{"wrong nullifier key under a correct viewing key", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].Utxo.NullifierPk = spptest.MustNullifierPk(t, big.NewInt(99))
		}},
		{"correct nullifier key under a wrong viewing key", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].RecipientKey = ringprotocol.XPublicKey(t, ringtest.Scalar(0x99))
			a.Reseal(t, 1)
		}},
		{"an address revision the record never held", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].AddressRevision = 2 }},
		{"an owner with no record", func(a *ringaudit.AnonymousAudit) {
			delete(a.Rows, a.Outputs[1].Utxo.OwnerPkHash.String())
		}},
		// A shared registry would let a record of one ring deliver for another.
		{"a record bound to another ring", func(a *ringaudit.AnonymousAudit) {
			slot := a.Outputs[1]
			a.Rows[slot.Utxo.OwnerPkHash.String()] = ringregistry.Address{RingID: big.NewInt(0x5a0f), Member: slot.Utxo.OwnerPkHash, NullifierPk: slot.Utxo.NullifierPk, ViewingKey: slot.RecipientKey, Revision: 1}.Hash(t)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape)
			tc.mutate(&a)
			requireFrame(t, a, deliverRecipients)
		})
	}
}

// The sender's row keys the bundle, change and the sender rules follow one address.
func TestSenderAddressBindsTheBundleKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"another viewing key", func(a *ringaudit.AnonymousAudit) {
			a.SenderViewingKey = ringprotocol.XPublicKey(t, ringtest.Scalar(0x99))
		}},
		{"another nullifier key", func(a *ringaudit.AnonymousAudit) { a.SenderNullifierPk = big.NewInt(0x1234) }},
		{"another revision", func(a *ringaudit.AnonymousAudit) { a.SenderAddressRevision = 2 }},
		{"a sender with no record", func(a *ringaudit.AnonymousAudit) { delete(a.Rows, a.SenderPkHash(t).String()) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape)
			tc.mutate(&a)
			requireFrame(t, a, deliverRecipients)
		})
	}
	// An older note spends into change at the bound address, the input's key is not the witness.
	t.Run("a note under an older nullifier key", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		a.Inputs[1].NullifierPk = big.NewInt(0x1234)
		compileAnonymous(t, deliveryShape).RequireSolved(t, a.Circuit(t))
	})
}

// No witness flag and no owner test decides change, the statement carries the one bitmap the addresses fix.
func TestChangeIsTheExactAddressMatch(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	claim := func(t *testing.T, edit func([]ringaudit.StatementOutput)) {
		t.Helper()
		honest := ringaudit.NewAnonymousAudit(t, deliveryShape)
		stream := honest.Stream(t)
		outputs := honest.StatementOutputs(t, stream)
		edit(outputs)
		head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
		c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, honest.Tail(t)))
	}
	t.Run("a payment claimed as change", func(t *testing.T) {
		claim(t, func(o []ringaudit.StatementOutput) { o[1].Change, o[1].Body = true, nil })
	})
	t.Run("change claimed as a payment", func(t *testing.T) {
		claim(t, func(o []ringaudit.StatementOutput) {
			o[0].Change, o[0].Body = false, make([]byte, shared.RecipientBodyLen)
		})
	})
	t.Run("the same owner at another viewing key is a payment", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		slot := a.Change(t, 1)
		slot.RecipientKey = ringprotocol.XPublicKey(t, ringtest.Scalar(0x99))
		// One leaf holds one address, the owner's row names the sender's.
		a.Outputs[1] = a.NewPayment(t, slot)
		a.Rows[a.SenderPkHash(t).String()] = ringregistry.Address{RingID: a.RingProgramID, Member: a.SenderPkHash(t), NullifierPk: a.SenderNullifierPk, ViewingKey: a.SenderViewingKey, Revision: 1}.Hash(t)
		requireFrame(t, a, deliverRecipients)
	})
	t.Run("a second change slot of native SOL", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		slot := a.Change(t, 1)
		slot.AssetAddress = [32]byte{}
		a.Outputs[1] = a.NewPayment(t, slot)
		c.RequireSolved(t, a.Circuit(t))
	})
	t.Run("a second change slot of another asset", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		a.Outputs[1] = a.NewPayment(t, a.Change(t, 1))
		requireFrame(t, a, "audit.AuditWires.sealSenderBundle")
	})
}

// A live slot's body is its opening, a recipient rebuilds the commitment from these bytes and nothing else.
func TestRecipientBodyEncryptsTheOpening(t *testing.T) {
	sealed := func(a *ringaudit.AnonymousAudit, body ringprotocol.RecipientBody, secret *big.Int) [shared.RecipientBodyLen]byte {
		return body.Seal(t, secret)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"another amount", func(a *ringaudit.AnonymousAudit) {
			o := a.Outputs[1]
			a.Outputs[1].Body = sealed(a, ringprotocol.RecipientBody{Blinding: o.Utxo.Blinding, Amount: o.Utxo.Amount + 1, Mint: o.Mint}, a.DeliveredSlotSecret(t, o.RecipientKey, 1))
		}},
		{"another mint", func(a *ringaudit.AnonymousAudit) {
			o := a.Outputs[1]
			a.Outputs[1].Body = sealed(a, ringprotocol.RecipientBody{Blinding: o.Utxo.Blinding, Amount: o.Utxo.Amount, Mint: ringtest.Repeat(0x0b)}, a.DeliveredSlotSecret(t, o.RecipientKey, 1))
		}},
		{"the secret of another slot", func(a *ringaudit.AnonymousAudit) {
			o := a.Outputs[1]
			a.Outputs[1].Body = sealed(a, ringprotocol.RecipientBody{Blinding: o.Utxo.Blinding, Amount: o.Utxo.Amount, Mint: o.Mint}, a.DeliveredSlotSecret(t, o.RecipientKey, 3))
		}},
		// One label per kind keeps a reply or a bundle off the body's keystream.
		{"the delivered body label", func(a *ringaudit.AnonymousAudit) {
			o := a.Outputs[1]
			key, nonce := ringprotocol.AuditStreamKeys(t, a.DeliveredSlotSecret(t, o.RecipientKey, 1), shared.BodyEncInfo)
			copy(a.Outputs[1].Body[:], ringprotocol.CTREncrypt(t, key, nonce, make([]byte, shared.RecipientBodyLen)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape)
			tc.mutate(&a)
			requireFrame(t, a, recipientBody)
		})
	}
	t.Run("a mint off the asset", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		a.Outputs[1].Mint = ringtest.Repeat(0x0b)
		a.Reseal(t, 1)
		requireFrame(t, a, deliverRecipients)
	})
	t.Run("a body on the chain other than the one sent", func(t *testing.T) {
		c := compileAnonymous(t, deliveryShape)
		honest := ringaudit.NewAnonymousAudit(t, deliveryShape)
		stream := honest.Stream(t)
		outputs := honest.StatementOutputs(t, stream)
		outputs[1].Body = slices.Clone(outputs[1].Body)
		outputs[1].Body[0] ^= 1
		head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
		c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, honest.Tail(t)))
	})
	t.Run("a published dummy's body hashes as sent", func(t *testing.T) {
		shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 8}
		c := compileAnonymous(t, shape)
		a := ringaudit.NewAnonymousAudit(t, shape)
		a.Outputs[6].Body[0] ^= 1
		c.RequireSolved(t, a.Circuit(t))
	})
}

// The bundle reads the slots' own wires, the sender rebuilds change and every recipient key from it.
func TestSenderBundleBindsTheSlots(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"another change amount", func(a *ringaudit.AnonymousAudit) { a.Outputs[0].Utxo.Amount++ }},
		{"another recipient key", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].RecipientKey = ringprotocol.XPublicKey(t, ringtest.Scalar(0x99))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			honest := ringaudit.NewAnonymousAudit(t, deliveryShape)
			other := ringaudit.NewAnonymousAudit(t, deliveryShape)
			tc.mutate(&other)
			tail := honest.Tail(t)
			tail.BundleDigest = ringprotocol.EnvelopeDigest(t, other.Bundle(t))
			stream := honest.Stream(t)
			head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
			c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, honest.StatementOutputs(t, stream), tail))
		})
	}
}

// Omission removes a suffix, every published slot keeps its index and every statement cell of an omitted slot reads zero.
func TestCompactPadding(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	for _, omitted := range []int{1, 2, 3} {
		c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, omitted).Circuit(t))
	}
	t.Run("a live note past the count", func(t *testing.T) {
		honest := ringaudit.NewAnonymousAudit(t, deliveryShape)
		a := honest
		a.Omitted = 1
		ringtest.RequireRefused(t, test.IsSolved(ringaudit.NewAnonymousCircuit(a.Shape), a.Circuit(t), ecc.BN254.ScalarField()), "audit.OpenSlots")
	})
	t.Run("a count of zero", func(t *testing.T) {
		assignment := ringaudit.NewAnonymousAudit(t, deliveryShape).Circuit(t)
		assignment.OutputCount = 0
		c.Refuse(t, assignment)
	})
	t.Run("a count past the capacity", func(t *testing.T) {
		assignment := ringaudit.NewAnonymousAudit(t, deliveryShape).Circuit(t)
		assignment.OutputCount = deliveryShape.Outputs + 1
		c.Refuse(t, assignment)
	})
	omittedHonest := func(t *testing.T) (ringaudit.AnonymousAudit, ringaudit.Stream) {
		t.Helper()
		a := ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, 1)
		return a, a.Stream(t)
	}
	// A cell an omitted slot publishes would let the frame and the proof disagree on the published slots.
	for _, tc := range []struct {
		name string
		edit func([]ringaudit.StatementOutput, *ringaudit.AnonymousTail)
	}{
		{"a statement count above the published slots", func(_ []ringaudit.StatementOutput, tail *ringaudit.AnonymousTail) { tail.OutputCount = 4 }},
		{"an omitted hash on the chain", func(o []ringaudit.StatementOutput, _ *ringaudit.AnonymousTail) { o[3].Omitted = false }},
		{"an omitted body on the chain", func(o []ringaudit.StatementOutput, _ *ringaudit.AnonymousTail) {
			o[3].Body = make([]byte, shared.RecipientBodyLen)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, stream := omittedHonest(t)
			outputs := a.StatementOutputs(t, stream)
			tail := a.Tail(t)
			tc.edit(outputs, &tail)
			head := a.AuditHead(t, a.Layout, stream.Envelope(a.InputCount))
			c.RefuseStatement(t, a.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, tail))
		})
	}
	// The bundle's index is m and its length follows m, a reader taking the capacity decrypts noise.
	t.Run("a bundle of the capacity", func(t *testing.T) {
		a, stream := omittedHonest(t)
		tail := a.Tail(t)
		full := ringaudit.NewAnonymousAudit(t, deliveryShape)
		tail.BundleDigest = ringprotocol.EnvelopeDigest(t, full.Bundle(t))
		head := a.AuditHead(t, a.Layout, stream.Envelope(a.InputCount))
		c.RefuseStatement(t, a.Circuit(t), ringaudit.AnonymousStatement(t, head, a.StatementOutputs(t, stream), tail))
	})
	t.Run("a published slot keeps its blinding", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, 1)
		a.Outputs[1].Utxo.Blinding = a.Blinding(t, 2)
		c.Refuse(t, a.Circuit(t))
	})
}

// A public co-owner spends beside the hidden sender, every other owner and an all public frame refuse.
func TestAnonymousPublicCoOwners(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	coOwner := big.NewInt(0x0c0c)
	withCoOwner := func(t *testing.T) ringaudit.AnonymousAudit {
		t.Helper()
		a := ringaudit.NewAnonymousAudit(t, deliveryShape)
		a.Inputs[2] = ringaudit.SpentUtxo(t, coOwner, a.SenderNullifierPk, a.RingProgramID, 5, 53)
		a.InputCount, a.Signers = 3, []*big.Int{coOwner}
		return a
	}
	c.RequireSolved(t, withCoOwner(t).Circuit(t))
	t.Run("an input owner outside the run", func(t *testing.T) {
		a := withCoOwner(t)
		a.Signers = []*big.Int{big.NewInt(0x0d0d)}
		c.Refuse(t, a.Circuit(t))
	})
	t.Run("the sender in the run", func(t *testing.T) {
		a := withCoOwner(t)
		a.Signers = []*big.Int{a.SenderPkHash(t), coOwner}
		c.Refuse(t, a.Circuit(t))
	})
	t.Run("a member past the count", func(t *testing.T) {
		a := withCoOwner(t)
		assignment := a.Circuit(t)
		assignment.Signers[1] = 0x0d0d
		c.Refuse(t, assignment)
	})
	// The run is the SPP owner signer run, another order or an extra signer names another transaction.
	for name, run := range map[string][]*big.Int{
		"a reordered run":  {big.NewInt(0x0d0d), coOwner},
		"an extra signer":  {coOwner, big.NewInt(0x0d0d), big.NewInt(0x0e0e)},
		"a missing signer": {coOwner},
		"an empty run":     {},
	} {
		t.Run(name, func(t *testing.T) {
			honest := withCoOwner(t)
			honest.Signers = []*big.Int{coOwner, big.NewInt(0x0d0d)}
			stream := honest.Stream(t)
			tail := honest.Tail(t)
			tail.SignerCount, tail.SignerChain = len(run), ringaudit.SignerChain(t, run, honest.Shape.InputClass)
			head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
			c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, honest.StatementOutputs(t, stream), tail))
		})
	}
	t.Run("an entry key binds no run", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, entryShape)
		assignment := a.Circuit(t)
		assignment.SignerCount = 1
		compileAnonymous(t, entryShape).Refuse(t, assignment)
	})
}

const slotTag = "audit.assertSlotTag"

// A scan finds a note only through its derived tag, a tag exists only where a slot can carry one.
func TestSlotTagIsDerived(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	dummies := audit.AnonymousAuditShape{InputClass: 4, Outputs: 8}
	t.Run("every slot kind solves", func(t *testing.T) {
		c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, deliveryShape).Circuit(t))
		compileAnonymous(t, dummies).RequireSolved(t, ringaudit.NewAnonymousAudit(t, dummies).Circuit(t))
		c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, 1).Circuit(t))
	})
	secretOf := func(a *ringaudit.AnonymousAudit, slot int) *big.Int {
		return a.DeliveredSlotSecret(t, a.Outputs[slot].RecipientKey, slot)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"a wrong tag on a live slot", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Tag = big.NewInt(7) }},
		// A live slot's tag is its derivation, the sender picks no value.
		{"the recipient key as a live tag", func(a *ringaudit.AnonymousAudit) {
			u := a.Outputs[1].RecipientKey
			a.Outputs[1].Tag = new(big.Int).Mod(new(big.Int).SetBytes(u[:]), ecc.BN254.ScalarField())
		}},
		// Each live slot derives from its own index.
		{"a repeated tag across live slots", func(a *ringaudit.AnonymousAudit) { a.Outputs[3].Tag = a.Outputs[1].Tag }},
		{"the tag of another slot's secret", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].Tag = ringprotocol.RecipientTag(t, secretOf(a, 3))
		}},
		{"a tag in the bundle's domain", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].Tag = ringprotocol.SenderBundleTag(t, secretOf(a, 1))
		}},
		// The selector is computed from the slot, a live slot cannot take the dummy's path.
		{"a live slot under a free preimage", func(a *ringaudit.AnonymousAudit) {
			a.Outputs[1].TagPreimage = big.NewInt(0xbad)
			a.Outputs[1].Tag = ringprotocol.RecipientTag(t, big.NewInt(0xbad))
		}},
		{"a nonzero tag on change", func(a *ringaudit.AnonymousAudit) { a.Outputs[0].Tag = big.NewInt(7) }},
		{"a nonzero tag on an exit", func(a *ringaudit.AnonymousAudit) { a.Outputs[2].Tag = big.NewInt(7) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape)
			tc.mutate(&a)
			requireFrame(t, a, slotTag)
		})
	}
	t.Run("a nonzero tag past the published count", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, 1)
		a.Outputs[3].Tag = big.NewInt(7)
		requireFrame(t, a, slotTag)
	})
	// One encoding covers live and dummy slots, a dummy tag needs a Poseidon(CRRT, s) preimage.
	t.Run("a dummy tag with no preimage", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, dummies)
		a.Outputs[6].Tag = big.NewInt(7)
		requireFrame(t, a, slotTag)
	})
	t.Run("a dummy tag under another preimage", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, dummies)
		a.Outputs[6].TagPreimage = big.NewInt(0xbad)
		requireFrame(t, a, slotTag)
	})
	t.Run("a dummy tag in the bundle's domain", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, dummies)
		a.Outputs[6].Tag = ringprotocol.SenderBundleTag(t, a.Outputs[6].TagPreimage)
		requireFrame(t, a, slotTag)
	})
	t.Run("a dummy with its own preimage", func(t *testing.T) {
		a := ringaudit.NewAnonymousAudit(t, dummies)
		a.Outputs[6].TagPreimage = big.NewInt(0x777)
		a.Outputs[6].Tag = ringprotocol.RecipientTag(t, big.NewInt(0x777))
		compileAnonymous(t, dummies).RequireSolved(t, a.Circuit(t))
	})
}

// The bundle's tag is derived on every anonymous transfer, a sender recovers a relayed proof through it alone.
func TestSenderBundleTagIsDerived(t *testing.T) {
	const deliver = "audit.AuditWires.DeliverRecipients"
	for _, tc := range []struct {
		name string
		tag  func(a ringaudit.AnonymousAudit) *big.Int
	}{
		{"a wrong tag", func(ringaudit.AnonymousAudit) *big.Int { return big.NewInt(7) }},
		{"a tag in the recipient's domain", func(a ringaudit.AnonymousAudit) *big.Int {
			return ringprotocol.RecipientTag(t, a.DeliveredSlotSecret(t, a.SenderViewingKey, a.OutputCount()))
		}},
		{"a tag of the capacity index", func(a ringaudit.AnonymousAudit) *big.Int {
			return ringprotocol.SenderBundleTag(t, a.DeliveredSlotSecret(t, a.SenderViewingKey, len(a.Outputs)))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape).Omit(t, 1)
			assignment := a.Circuit(t)
			assignment.SenderBundleTag = tc.tag(a)
			ringtest.RequireRefused(t, test.IsSolved(ringaudit.NewAnonymousCircuit(a.Shape), assignment, ecc.BN254.ScalarField()), deliver)
		})
	}
}

// The chain carries the frame's tags in slot order with zero where no tag exists, another frame names another statement.
func TestRecipientTagChainBindsTheFrame(t *testing.T) {
	c := compileAnonymous(t, deliveryShape)
	for _, tc := range []struct {
		name string
		edit func([]ringaudit.StatementOutput, *ringaudit.AnonymousTail)
	}{
		{"two tags swapped", func(o []ringaudit.StatementOutput, _ *ringaudit.AnonymousTail) {
			o[1].Tag, o[3].Tag = o[3].Tag, o[1].Tag
		}},
		{"a nonzero change cell", func(o []ringaudit.StatementOutput, _ *ringaudit.AnonymousTail) { o[0].Tag = big.NewInt(7) }},
		{"a nonzero exit cell", func(o []ringaudit.StatementOutput, _ *ringaudit.AnonymousTail) { o[2].Tag = big.NewInt(7) }},
		{"another bundle tag", func(_ []ringaudit.StatementOutput, tail *ringaudit.AnonymousTail) { tail.BundleTag = big.NewInt(7) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, deliveryShape)
			stream := a.Stream(t)
			outputs := a.StatementOutputs(t, stream)
			tail := a.Tail(t)
			tc.edit(outputs, &tail)
			head := a.AuditHead(t, a.Layout, stream.Envelope(a.InputCount))
			c.RefuseStatement(t, a.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, tail))
		})
	}
}
