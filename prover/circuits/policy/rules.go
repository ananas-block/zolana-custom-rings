package policy

import (
	"errors"
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Payment is an output slot or a withdrawal leg as the policy screens it, inactive on a dummy or past the count. Ring is set on a same-ring output, the one payment an input of its owner nets.
type Payment struct{ Owner, Asset, Amount, Active, Ring frontend.Variable }

func slotPayments(slots []shared.Output) []Payment {
	payments := make([]Payment, len(slots))
	for i, slot := range slots {
		payments[i] = Payment{Owner: slot.OwnerPkHash, Asset: slot.Asset, Amount: slot.Amount, Active: slot.Utxo, Ring: slot.Ring}
	}
	return payments
}

func screenedRules(api frontend.API, screened frontend.Variable, table tableView) []frontend.Variable {
	active := make([]frontend.Variable, len(table.rules))
	for r := range table.rules {
		active[r] = api.Mul(screened, table.ruleActive[r])
	}
	return active
}

// assertSenderRules holds every screened sender to every sender rule, with or without a spent input or an output.
func assertSenderRules(api frontend.API, active []frontend.Variable, table tableView, resolved subjects) {
	for r, rule := range table.rules {
		for j, sender := range resolved.senders {
			abstractor.CallVoid(api, gadget.AssertZeroWhen{Cond: api.Mul(active[r], rule.onSender, resolved.liveSenders[j]), V: rule.refuses(api, sender.onList)})
		}
	}
}

// assertPaymentRules holds every live payment's owner and asset to every rule on them, inputs net same-ring receipts.
func assertPaymentRules(api frontend.API, cmp comparator, active []frontend.Variable, table tableView, resolved subjects, payments []Payment, inputs []shared.Output) {
	screen := newPaymentScreen(api, cmp, resolved, payments, inputs)
	for r, rule := range table.rules {
		screen.assert(api, rule, api.Mul(active[r], api.Add(rule.onOwner, rule.onAsset)))
	}
}

// paymentGuard is guard(owner, asset) of a payment and the sum of guard over its asset.
type paymentGuard struct{ owner, asset frontend.Variable }

type paymentScreen struct {
	cmp                    comparator
	resolved               subjects
	payments               []Payment
	liveOwner, assetExempt []frontend.Variable
	guards                 []paymentGuard
}

func newPaymentScreen(api frontend.API, cmp comparator, resolved subjects, payments []Payment, inputs []shared.Output) paymentScreen {
	// 1. A zero owner carries no obligation, an asset needs no such gate since SPP refuses a UTXO of asset 0.
	liveOwner := make([]frontend.Variable, len(payments))
	for o, pay := range payments {
		liveOwner[o] = api.Mul(pay.Active, ringgadget.IsNonZero(api, pay.Owner))
	}
	// 2. A mint without a threshold reads zero, a positive guard then needs the lists.
	guards := paymentGuards(api, cmp, payments, inputs)
	assetExempt := make([]frontend.Variable, len(payments))
	for o := range payments {
		assetExempt[o] = cmp.atMost(api, guards[o].owner, resolved.mintPolicies[o].threshold)
	}
	return paymentScreen{cmp: cmp, resolved: resolved, payments: payments, liveOwner: liveOwner, assetExempt: assetExempt, guards: guards}
}

// assert holds one rule for every live payment while onPayment is set.
func (s paymentScreen) assert(api frontend.API, rule ruleFields, onPayment frontend.Variable) {
	for o := range s.payments {
		enabled := api.Mul(onPayment, api.Select(rule.onAsset, s.payments[o].Active, s.liveOwner[o]))
		refused := rule.refuses(api, subjectLists(api, rule.onAsset, s.resolved.assets[o], s.resolved.owners[o]))
		total := api.Select(rule.onAsset, s.guards[o].asset, s.guards[o].owner)
		scalar := api.Mul(rule.scalarGuard, s.cmp.atMost(api, total, rule.threshold))
		exempt := api.Or(scalar, api.Mul(rule.assetGuard, s.assetExempt[o]))
		// A subject the lists refuse needs its amounts within the rule's guard.
		transaction.AssertWhen(api, api.Mul(enabled, refused), exempt)
	}
}

// paymentGuards gives each payment receipt + exit + paid of its owner and asset, and the sum of that over its asset's distinct owners.
func paymentGuards(api frontend.API, cmp comparator, payments []Payment, inputs []shared.Output) []paymentGuard {
	n := len(payments)
	// 1. Ring amounts net against same-ring inputs, an exit or a withdrawal stays gross.
	ringAmounts, grossAmounts := make([]frontend.Variable, n), make([]frontend.Variable, n)
	received, passing, repeats := make([]frontend.Variable, n), make([]frontend.Variable, n), make([]frontend.Variable, n)
	sameAsset := make([][]frontend.Variable, n)
	for p, pay := range payments {
		amount := api.Mul(pay.Active, pay.Amount)
		ringAmounts[p] = api.Mul(pay.Ring, amount)
		grossAmounts[p] = api.Sub(amount, ringAmounts[p])
		received[p], passing[p], repeats[p] = ringAmounts[p], grossAmounts[p], 0
		sameAsset[p] = make([]frontend.Variable, n)
		sameAsset[p][p] = 1
	}
	// 2. Each pair folds once, repeats counts the earlier live payments of one owner and asset.
	for p := range payments {
		for q := range payments[:p] {
			sameAsset[p][q] = api.IsZero(api.Sub(payments[p].Asset, payments[q].Asset))
			sameAsset[q][p] = sameAsset[p][q]
			samePair := api.Mul(sameAsset[p][q], api.IsZero(api.Sub(payments[p].Owner, payments[q].Owner)))
			received[p] = api.Add(received[p], api.Mul(samePair, ringAmounts[q]))
			received[q] = api.Add(received[q], api.Mul(samePair, ringAmounts[p]))
			passing[p] = api.Add(passing[p], api.Mul(samePair, grossAmounts[q]))
			passing[q] = api.Add(passing[q], api.Mul(samePair, grossAmounts[p]))
			repeats[p] = api.Add(repeats[p], api.Mul(samePair, payments[q].Active))
		}
	}
	// 3. A default-ring input reads no Ring flag, entry funding stays a receipt.
	guards := make([]paymentGuard, n)
	for p, pay := range payments {
		spent := frontend.Variable(0)
		for _, input := range inputs {
			held := api.Mul(input.Ring, api.IsZero(api.Sub(input.OwnerPkHash, pay.Owner)), api.IsZero(api.Sub(input.Asset, pay.Asset)))
			spent = api.Add(spent, api.Mul(held, input.Amount))
		}
		receipt := api.Select(cmp.atMost(api, received[p], spent), 0, api.Sub(received[p], spent))
		guards[p].owner = api.Add(receipt, passing[p])
	}
	// 4. Only the first payment of an owner and asset counts toward the asset's sum.
	for p := range payments {
		guards[p].asset = 0
		for q, pay := range payments {
			first := api.Mul(pay.Active, api.IsZero(repeats[q]))
			guards[p].asset = api.Add(guards[p].asset, api.Mul(sameAsset[p][q], first, guards[q].owner))
		}
	}
	return guards
}

// refuses is set when no list admits the subject, neither a present list it is on nor an absent list it is off.
func (r ruleFields) refuses(api frontend.API, onList [NSources]frontend.Variable) frontend.Variable {
	admitting := r.admitBase
	for i, on := range onList {
		admitting = api.Add(admitting, api.Mul(on, r.admitWeight[i]))
	}
	// Each list adds 0, 1 or 2, the count is zero exactly when no list admits the subject.
	return api.IsZero(admitting)
}

func subjectLists(api frontend.API, onAsset frontend.Variable, asset, owner subjectView) [NSources]frontend.Variable {
	var onList [NSources]frontend.Variable
	for i := range onList {
		onList[i] = api.Select(onAsset, asset.onList[i], owner.onList[i])
	}
	return onList
}

type comparator struct {
	rc frontend.Rangechecker
	// width bounds every difference the key compares, fixed when the key compiles.
	width int
}

func newComparator(rc frontend.Rangechecker) comparator {
	return comparator{rc: rc, width: debitBits}
}

// atMost returns total <= threshold, the caller bounds their difference below 2^width in magnitude.
func (c comparator) atMost(api frontend.API, total, threshold frontend.Variable) frontend.Variable {
	offset := new(big.Int).Lsh(big.NewInt(1), uint(c.width))
	delta := api.Add(api.Sub(threshold, total), offset)
	// 1. The hint proposes the low width bits and the top bit of delta, untrusted until the checks below bind them.
	parts, err := api.Compiler().NewHint(comparisonHint, 2, delta, c.width)
	if err != nil {
		panic(err)
	}
	low, top := parts[0], parts[1]
	// 2. low below 2^width leaves one split per delta.
	c.rc.Check(low, c.width)
	// 3. top is a bit, the split then covers delta below 2^(width+1) only.
	api.AssertIsBoolean(top)
	// 4. delta lies in (0, 2^(width+1)), its split is unique and top is set exactly when total <= threshold.
	api.AssertIsEqual(delta, api.Add(low, api.Mul(top, offset)))
	return top
}

// min returns the smaller of a and b, the caller bounds their difference as atMost needs.
func (c comparator) min(api frontend.API, a, b frontend.Variable) frontend.Variable {
	return api.Select(c.atMost(api, a, b), a, b)
}

func init() { solver.RegisterHint(comparisonHint) }

// comparisonHint splits delta at the width, atMost range checks and recomposes both parts.
func comparisonHint(_ *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 2 || len(outputs) != 2 || !inputs[1].IsUint64() {
		return errors.New("comparison: want delta, width and two outputs")
	}
	width := uint(inputs[1].Uint64())
	mask := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), width), big.NewInt(1))
	outputs[0].And(inputs[0], mask)
	outputs[1].Rsh(inputs[0], width)
	return nil
}

// assertRecipients holds each statement recipient to its slot's owner identity while screened and published, zero otherwise.
func (p *PolicyInputs) assertRecipients(api frontend.API, screened, published frontend.Variable, outputs []shared.Output) {
	for o, out := range outputs {
		// The owner rules screen the same OwnerPkHash.
		api.AssertIsEqual(p.Recipients[o], api.Mul(screened, published, out.Utxo, out.OwnerPkHash))
	}
}
