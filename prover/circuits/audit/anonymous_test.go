// Pins the anonymous section's refusals over slots, evidence, records and the published count.

package audit_test

import (
	"fmt"
	"math"
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// entryShape is the cheapest entry layout, its fixture spends a ring note and a default-ring note.
var entryShape = audit.AnonymousAuditShape{InputClass: 8, Outputs: 2, FullOpenings: true}

// sectionShapes are the commitment classes and entry layouts the section tests sweep, the transfer keys' among them.
var sectionShapes = []audit.AnonymousAuditShape{
	{InputClass: 4, Outputs: 2}, {InputClass: 16, Outputs: 2}, {InputClass: 24, Outputs: 2},
	{InputClass: 4, Outputs: 4}, {InputClass: 16, Outputs: 4},
	{InputClass: 4, Outputs: 8}, {InputClass: 5, Outputs: 8}, {InputClass: 8, Outputs: 8},
	entryShape, {InputClass: 8, Outputs: 4, FullOpenings: true}, {InputClass: 2, Outputs: 8, FullOpenings: true}, {InputClass: 8, Outputs: 8, FullOpenings: true},
}

// Every commitment class and entry layout solves its honest fixture.
func TestAnonymousAuditSolvesEveryShape(t *testing.T) {
	for _, shape := range sectionShapes {
		t.Run(anonymousKeyName(shape), func(t *testing.T) {
			c, ok := compiledAudits[anonymousKeyName(shape)]
			if !ok {
				c = ringkey.Bind(t, ringaudit.NewAnonymousCircuit(shape), ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
			}
			c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, shape).Circuit(t))
		})
	}
}

// The entry key opens a ring note and a default-ring note, with and without an exit.
func TestAnonymousEntrySolvesBothLayouts(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	a := ringaudit.NewAnonymousAudit(t, entryShape)
	c.RequireSolved(t, a.Circuit(t))
	a.Outputs[1] = a.NewAnonymousExit(t, 1)
	c.RequireSolved(t, a.Circuit(t))
}

// Every published input count solves on a commitment key and on the entry key.
func TestAnonymousAuditSolvesEveryInputCount(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		c := compileAnonymous(t, shape)
		for count := 1; count <= shape.InputClass; count++ {
			t.Run(fmt.Sprintf("%s/%d", anonymousKeyName(shape), count), func(t *testing.T) {
				a := ringaudit.NewAnonymousAudit(t, shape).AtInputCount(count)
				c.RequireSolved(t, a.Circuit(t))
			})
		}
	}
}

// Each case changes one value of an honest transfer of two payments, an exit and change in slots 0 to 3.
func TestAnonymousAuditRefusals(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	stranger := ringtest.Repeat(0xc3)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"ring output with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.RingDataHash = big.NewInt(5) }},
		{"exit with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[2].Utxo.RingDataHash = big.NewInt(5) }},
		{"ring output with a data hash", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.DataHash = big.NewInt(5) }},
		{"owner key not the slot owner", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].OwnerKey[0] ^= 1 }},
		{"UTXO input at the input count", func(a *ringaudit.AnonymousAudit) { a.InputCount = 1 }},
		{"input of another owner", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].OwnerPkHash = ringtest.MustSolanaPkField(t, stranger) }},
		{"input 0 a dummy", func(a *ringaudit.AnonymousAudit) { a.Inputs[0] = ringaudit.Dummy(3, big.NewInt(0x9000)) }},
		{"committed input of the default ring", func(a *ringaudit.AnonymousAudit) { a.Inputs[1] = a.SenderUtxo(t, big.NewInt(0), 60, 52) }},
		{"full openings on a commitment key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = true }},
		{"escrow flag on an anonymous key", func(a *ringaudit.AnonymousAudit) { a.Layout.Escrow = true }},
		{"ring output blinding of another slot", func(a *ringaudit.AnonymousAudit) { a.Outputs[1].Utxo.Blinding = a.Blinding(t, 0) }},
		{"exit blinding off the CRBS seed", func(a *ringaudit.AnonymousAudit) { a.Outputs[2].Utxo.Blinding = big.NewInt(0x5ec) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			tc.mutate(&a)
			c.Refuse(t, a.Circuit(t))
		})
	}
}

// A live amount of 2^64 - 1 solves and 2^64 fails its decomposition, on a ring output and an exit alike.
func TestAnonymousAmountsStayBelowTwoTo64(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	for name, slot := range map[string]int{"ring output": 1, "exit": 2} {
		t.Run(name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			a.Outputs[slot].Utxo.Amount = math.MaxUint64
			c.RequireSolved(t, a.Circuit(t))
			assignment := a.Circuit(t)
			assignment.Outputs[slot].Output.Amount = new(big.Int).Lsh(big.NewInt(1), 64)
			c.Refuse(t, assignment)
		})
	}
}

// A dummy ahead of a spent UTXO moves the note off its nullifier.
func TestAnonymousInputsKeepDummiesLast(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		t.Run(anonymousKeyName(shape), func(t *testing.T) {
			c := compileAnonymous(t, shape)
			trailing := ringaudit.NewAnonymousAudit(t, shape).AtInputCount(3)
			c.RequireSolved(t, trailing.Circuit(t))
			gap := trailing
			gap.Inputs = slices.Clone(trailing.Inputs)
			gap.Inputs[1], gap.Inputs[2] = gap.Inputs[2], gap.Inputs[1]
			if gap.PrivateTxHash(t).Cmp(trailing.PrivateTxHash(t)) != 0 {
				t.Fatal("the gap changed SPP's private transaction hash")
			}
			c.Refuse(t, gap.Circuit(t))
		})
	}
}

// A spent hash below 2^254 - q has a second 32-byte encoding, hash + q, the canonical bound refuses its prefix.
func TestAnonymousSpentPrefixRefusesTheAliasEncoding(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 2}
	c := compileAnonymous(t, shape)
	q := ecc.BN254.ScalarField()
	limit := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 254), q)
	for blinding := int64(52); blinding < 116; blinding++ {
		a := ringaudit.NewAnonymousAudit(t, shape)
		a.Inputs[1] = a.SenderUtxo(t, a.RingProgramID, 60, blinding)
		hash := a.Inputs[1].Hash(t)
		if hash.Cmp(limit) >= 0 {
			continue
		}
		c.RequireSolved(t, a.Circuit(t))
		c.Refuse(t, a.Circuit(t), encodingOf(t, hash, new(big.Int).Add(hash, q)))
		return
	}
	t.Fatal("no fixture hash below 2^254 - q")
}

// The evidence ends at the published count, a count that opens another range hashes apart.
func TestAnonymousEvidenceFollowsTheInputCount(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		t.Run(anonymousKeyName(shape), func(t *testing.T) {
			c := compileAnonymous(t, shape)
			honest := ringaudit.NewAnonymousAudit(t, shape)
			// The frame's nullifier count must hold the evidence selection, the auditor would miss an input.
			t.Run("a statement count over another envelope", func(t *testing.T) {
				tail := honest.Tail(t)
				tail.InputCount++
				stream := honest.Stream(t)
				head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
				c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, honest.StatementOutputs(t, stream), tail))
			})
			// The length tag and the chain end follow the count, a longer cut hashes apart.
			t.Run("an envelope cut at another count", func(t *testing.T) {
				stream := honest.Stream(t)
				head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount+1))
				c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, honest.StatementOutputs(t, stream), honest.Tail(t)))
			})
			t.Run("a count past the class", func(t *testing.T) {
				assignment := honest.Circuit(t)
				assignment.InputCount = shape.InputClass + 1
				c.Refuse(t, assignment)
			})
		})
	}
}

// A record reads its slot alone, the statement binds each to its position.
func TestAnonymousRecordsStayOnTheirSlots(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	honest := ringaudit.NewAnonymousAudit(t, shape)
	stream := honest.Stream(t)
	head := honest.AuditHead(t, honest.Layout, stream.Envelope(honest.InputCount))
	// The chain reads position, the auditor would book one output's opening to another.
	t.Run("a record swapped between slots", func(t *testing.T) {
		outputs := honest.StatementOutputs(t, stream)
		outputs[0].Ciphertext, outputs[1].Ciphertext = outputs[1].Ciphertext, outputs[0].Ciphertext
		c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, honest.Tail(t)))
	})
	t.Run("a record of the plaintexts swapped between slots", func(t *testing.T) {
		records := honest.Records(t)
		records[0], records[1] = records[1], records[0]
		c.RefuseStatement(t, honest.Circuit(t), honest.StatementOver(t, honest.StreamOf(t, honest.Evidence(t), records)))
	})
	// The program cuts lengths from the bitmap, the circuit derives it from the opened slots.
	t.Run("changed exit positions", func(t *testing.T) {
		outputs := honest.StatementOutputs(t, stream)
		outputs[1].Exit, outputs[2].Exit = true, false
		c.RefuseStatement(t, honest.Circuit(t), ringaudit.AnonymousStatement(t, head, outputs, honest.Tail(t)))
	})
}

// The widest class solves at both ends of its counts and across a pair boundary.
func TestAnonymousWideClassSolves(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 16, Outputs: 2}
	c := compileAnonymous(t, shape)
	for _, count := range []int{1, 2, 3, 15, 16} {
		t.Run(fmt.Sprintf("%s/%d", anonymousKeyName(shape), count), func(t *testing.T) {
			c.RequireSolved(t, ringaudit.NewAnonymousAudit(t, shape).AtInputCount(count).Circuit(t))
		})
	}
}

func encodingOf(t *testing.T, value, alias *big.Int) solver.Option {
	t.Helper()
	honest := ringtest.RegisteredHint(t, "/ringgadget.fieldBytesHint")
	return solver.OverrideHint(solver.GetHintID(honest), func(field *big.Int, inputs, outputs []*big.Int) error {
		if inputs[0].Cmp(value) == 0 {
			return honest(field, []*big.Int{alias}, outputs)
		}
		return honest(field, inputs, outputs)
	})
}

// Each case changes one value of an honest entry transfer whose input 0 is a ring note and input 1 a default-ring note.
func TestAnonymousEntryRefusals(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for _, tc := range []struct {
		name   string
		mutate func(*ringaudit.AnonymousAudit)
	}{
		{"input with a data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[1].DataHash = big.NewInt(5) }},
		{"ring note with a ring data hash", func(a *ringaudit.AnonymousAudit) { a.Inputs[0].RingDataHash = big.NewInt(5) }},
		{"input under another nullifier key than input 0", func(a *ringaudit.AnonymousAudit) {
			a.Inputs[1].NullifierPk = spptest.MustNullifierPk(t, big.NewInt(8))
		}},
		{"input hashes on an entry key", func(a *ringaudit.AnonymousAudit) { a.Layout.FullOpenings = false }},
		{"sender key of another owner", func(a *ringaudit.AnonymousAudit) {
			a.SenderKey = ringtest.Repeat(0xc3)
			a.Outputs[1] = a.NewPayment(t, a.Change(t, 1))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, entryShape)
			tc.mutate(&a)
			c.Refuse(t, a.Circuit(t))
		})
	}
}

// A commitment key's evidence holds input 0's hash and the prefix of every other spent hash, evidence naming another note fails the statement.
func TestAnonymousEvidenceHoldsInputHashAndPrefixes(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	honest := ringaudit.NewAnonymousAudit(t, shape)
	other := honest
	other.Inputs = slices.Clone(honest.Inputs)
	other.Inputs[1].Blinding = big.NewInt(53)
	refuseOtherDisclosure(t, c, honest, other)
}

// An entry key's evidence opens every spent UTXO under input 0's nullifier key, evidence of another opening fails the statement.
func TestAnonymousEntryEvidenceOpensEachInput(t *testing.T) {
	c := compileAnonymous(t, entryShape)
	for name, edit := range map[string]func([]ringaudit.Utxo){
		"asset":         func(u []ringaudit.Utxo) { u[1].Asset = ringtest.AssetField(t, ringtest.Repeat(0x0b)) },
		"amount":        func(u []ringaudit.Utxo) { u[1].Amount++ },
		"blinding":      func(u []ringaudit.Utxo) { u[1].Blinding = big.NewInt(53) },
		"nullifier key": func(u []ringaudit.Utxo) { u[0].NullifierPk = big.NewInt(0x1234) },
	} {
		t.Run(name, func(t *testing.T) {
			honest := ringaudit.NewAnonymousAudit(t, entryShape)
			other := honest
			other.Inputs = slices.Clone(honest.Inputs)
			edit(other.Inputs)
			refuseOtherDisclosure(t, c, honest, other)
		})
	}
}

// A ring output's owner key and every UTXO's asset, amount and nullifier key reach the auditor, a record of another opening fails the statement.
func TestAnonymousRecordsOpenTheirSlot(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 4}
	c := compileAnonymous(t, shape)
	edits := map[string]func(*ringaudit.AnonymousOutput){
		"asset":         func(o *ringaudit.AnonymousOutput) { o.Utxo.Asset = ringtest.AssetField(t, ringtest.Repeat(0x0b)) },
		"amount":        func(o *ringaudit.AnonymousOutput) { o.Utxo.Amount++ },
		"nullifier key": func(o *ringaudit.AnonymousOutput) { o.Utxo.NullifierPk = big.NewInt(0x1234) },
		"owner key":     func(o *ringaudit.AnonymousOutput) { o.OwnerKey[0] ^= 1 },
	}
	for slotName, slot := range map[string]int{"ring output": 1, "exit": 2} {
		for name, edit := range edits {
			if slotName == "exit" && name == "owner key" {
				continue
			}
			t.Run(slotName+"/"+name, func(t *testing.T) {
				honest := ringaudit.NewAnonymousAudit(t, shape)
				other := honest
				other.Outputs = slices.Clone(honest.Outputs)
				edit(&other.Outputs[slot])
				refuseOtherDisclosure(t, c, honest, other)
			})
		}
	}
}

// An exit's record holds no owner key and a dummy's only zeros, a record of any other bytes fails the statement.
func TestAnonymousRecordsKeepTheirKind(t *testing.T) {
	shape := audit.AnonymousAuditShape{InputClass: 4, Outputs: 8}
	c := compileAnonymous(t, shape)
	const exit, dummy = 3, 6
	for _, tc := range []struct {
		name   string
		tamper func(a ringaudit.AnonymousAudit, records [][]byte)
	}{
		{"exit owner key", func(a ringaudit.AnonymousAudit, records [][]byte) {
			records[exit] = slices.Concat(ringaudit.ExitOwnerKey[:], records[exit])
		}},
		{"dummy owner key", func(a ringaudit.AnonymousAudit, records [][]byte) { copy(records[dummy], a.Outputs[dummy].OwnerKey[:]) }},
		{"dummy asset", func(a ringaudit.AnonymousAudit, records [][]byte) { records[dummy][63] = 1 }},
		{"dummy amount", func(a ringaudit.AnonymousAudit, records [][]byte) { records[dummy][71] = 1 }},
		{"dummy nullifier key", func(a ringaudit.AnonymousAudit, records [][]byte) { records[dummy][103] = 1 }},
		// Each case hands the auditor bytes its slot kind cannot hold, the program's chain must miss the proof's.
		{"ring output without its owner key", func(a ringaudit.AnonymousAudit, records [][]byte) { clear(records[0][:32]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := ringaudit.NewAnonymousAudit(t, shape)
			records := a.Records(t)
			tc.tamper(a, records)
			c.RefuseStatement(t, a.Circuit(t), a.StatementOver(t, a.StreamOf(t, a.Evidence(t), records)))
		})
	}
}

func refuseOtherDisclosure(t *testing.T, c *ringkey.Bound, honest, other ringaudit.AnonymousAudit) {
	t.Helper()
	c.RefuseStatement(t, honest.Circuit(t), honest.StatementOver(t, other.Stream(t)))
}

// Rebinding a forbidden party into a valid statement cannot bypass the circuit.
func TestAnonymousParties(t *testing.T) {
	for _, shape := range []audit.AnonymousAuditShape{{InputClass: 4, Outputs: 2}, entryShape} {
		c := compileAnonymous(t, shape)
		for i := range 3 {
			a := ringaudit.NewAnonymousAudit(t, shape)
			a.PartyIdentities[i] = a.SenderPkHash(t)
			c.Refuse(t, a.Circuit(t))
			a.PartyIdentities[i] = big.NewInt(0)
			c.RequireSolved(t, a.Circuit(t))
			assignment := a.Circuit(t)
			assignment.PartyIdentities[i] = 99 // differs from the verifier's bound identity
			c.RefuseStatement(t, assignment, a.Statement(t))
		}
	}
}
