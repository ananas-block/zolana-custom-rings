package transfer_test

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/policy"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func hexes(values []*big.Int) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = ringtest.FieldHex(value)
	}
	return out
}

func bytesHex(value []byte) string {
	return hex.EncodeToString(value)
}

// vectorOf holds every preimage the program reads from a frame, omitted slots absent.
func vectorOf(t *testing.T, name, family string, s ringtransfer.Statement, signers []*big.Int, signerSlots int, p *policy.Policy) transferStatementVector {
	t.Helper()
	v := transferStatementVector{
		Name: name, Family: family, InProof: s.InProof, Delegate: s.Delegate, Exempt: s.Exempt, ApprovalRequired: s.ApprovalRequired,
		FirstNullifier: ringtest.FieldHex(s.Head.FirstNullifier), RingProgramID: ringtest.FieldHex(s.Head.RingProgramID),
		TxViewingU: bytesHex(s.Head.TxViewingU[:]), AuditorPubkey: bytesHex(s.Head.AuditorPubkey[:]), EphU: bytesHex(s.Head.EphU[:]),
		Envelope: bytesHex(s.Head.Envelope), Salt: bytesHex(s.Head.Salt[:]), Layout: s.Head.Layout,
		OutputCapacity: len(s.Outputs), OutputCount: ringaudit.OutputCount(s.Outputs), InputCount: s.InputCount,
		PrivateTxHash: ringtest.FieldHex(s.PrivateTxHash), SignerSlots: signerSlots, Signers: hexes(signers), SignerCount: s.SignerCount, SignerChain: ringtest.FieldHex(s.SignerChain),
		PolicyHash: ringtest.FieldHex(s.PolicyHash), OwnRoot: ringtest.FieldHex(s.OwnRoot), CuratorRoot: ringtest.FieldHex(s.CuratorRoot), WithdrawalHash: ringtest.FieldHex(s.WithdrawalHash),
	}
	for k := range s.PublicAssets {
		v.PublicAssets[k], v.PublicAmounts[k], v.PublicGross[k] = ringtest.FieldHex(s.PublicAssets[k]), ringtest.FieldHex(s.PublicNets[k]), ringtest.FieldHex(s.PublicGross[k])
	}
	for _, leg := range p.Withdrawals[:int(ringtest.AsBigInt(p.WithdrawalCount).Int64())] {
		v.Withdrawals = append(v.Withdrawals, withdrawalVector{Owner: ringtest.FieldHex(ringtest.AsBigInt(leg.Owner)), Asset: ringtest.FieldHex(ringtest.AsBigInt(leg.Asset)), Amount: ringtest.AsBigInt(leg.Amount).Uint64()})
	}
	for _, output := range s.Outputs {
		if output.Omitted {
			continue
		}
		o := statementOutputVector{Hash: ringtest.FieldHex(output.Hash)}
		switch {
		case output.Exit:
			o.Kind, o.Record = "exit", bytesHex(output.Ciphertext)
		case family == "confidential":
			o.Kind, o.U, o.Body = "delivered", bytesHex(output.U[:]), bytesHex(output.Ciphertext)
		default:
			o.Kind, o.Record = "anonymous", bytesHex(output.Ciphertext)
			if output.Body != nil {
				o.RecipientBody = bytesHex(output.Body)
			}
			if output.Tag != nil {
				o.Tag = ringtest.FieldHex(output.Tag)
			}
		}
		v.Outputs = append(v.Outputs, o)
	}
	if family == "confidential" {
		v.Sender = ringtest.FieldHex(s.Sender)
		v.Recipients = hexes(s.Recipients[:v.OutputCount])
		return v
	}
	v.PartyIdentities = hexes(s.PartyIdentities[:])
	v.SenderBundleTag = ringtest.FieldHex(s.BundleTag)
	bitmap := ringaudit.ChangeBitmap(s.Outputs).Uint64()
	v.ChangeBitmap = &bitmap
	return v
}

// closed requires the vector's preimages alone to reach the statement the witness solved.
func closed(t *testing.T, v transferStatementVector, elements []*big.Int) transferStatementVector {
	t.Helper()
	v.Elements, v.PublicInputHash = hexes(elements), ringtest.FieldHex(spptest.MustHashChain4(t, elements))
	requireElements(t, v.elements(t), v.Elements, v.PublicInputHash)
	signers := make([]*big.Int, len(v.Signers))
	for i, signer := range v.Signers {
		signers[i] = ringtest.VectorField(t, signer)
	}
	if chain := ringtest.FieldHex(ringaudit.SignerChain(t, signers, v.SignerSlots)); chain != v.SignerChain {
		t.Fatalf("%s: signer chain %s, the vector holds %s", v.Name, chain, v.SignerChain)
	}
	legs := []*big.Int{big.NewInt(shared.WithdrawalsDomain), big.NewInt(int64(len(v.Withdrawals)))}
	for _, leg := range v.Withdrawals {
		legs = append(legs, ringtest.VectorField(t, leg.Owner), ringtest.VectorField(t, leg.Asset), new(big.Int).SetUint64(leg.Amount))
	}
	if hash := ringtest.FieldHex(spptest.MustHashChain4(t, legs)); hash != v.WithdrawalHash {
		t.Fatalf("%s: withdrawal hash %s, the vector holds %s", v.Name, hash, v.WithdrawalHash)
	}
	return v
}

func confidentialCase(t *testing.T, name string, w ringtransfer.Confidential) transferStatementVector {
	t.Helper()
	b := w.Build(t)
	values, elements := b.Values(t), b.Statement(t)
	v := vectorOf(t, name, "confidential", values, b.Run, w.Shape.Inputs, &b.Circuit.Policy)
	requireSolved(t, b.Circuit)
	if len(elements) != 41+w.Shape.Outputs {
		t.Fatalf("%s holds %d elements, the family fixes %d", name, len(elements), 41+w.Shape.Outputs)
	}
	return closed(t, v, elements)
}

// anonymousCase carries replies as the reply region, nil without reply metadata.
func anonymousCase(t *testing.T, name string, w ringtransfer.Anonymous, replies []byte) transferStatementVector {
	t.Helper()
	b := w.Build(t)
	if replies != nil {
		b.Circuit.ReplyDigest = ringprotocol.EnvelopeDigest(t, replies)
		b.Rebind(t)
	}
	values, elements := b.Values(t), b.Statement(t)
	slots := w.Shape.InputClass
	if w.Shape.FullOpenings {
		slots = 0
	}
	v := vectorOf(t, name, "anonymous", values, b.Audit.Signers, slots, &b.Circuit.Policy)
	v.SenderBundle = bytesHex(b.Audit.Bundle(t))
	if replies != nil {
		v.Replies = bytesHex(replies)
	}
	requireSolved(t, b.Circuit)
	if len(elements) != 45 {
		t.Fatalf("%s holds %d elements, the family fixes 45", name, len(elements))
	}
	return closed(t, v, elements)
}

// The pinned honest witnesses solve the circuits, a Rust or TypeScript builder reaching these elements from the preimages reaches a statement the key proves.
func TestTransferStatementVectorV3(t *testing.T) {
	compact := ringtransfer.Signed(transfer.ConfidentialShape{Inputs: 24, Outputs: 4, Withdrawals: 4})
	compact.Exits, compact.Omitted = []int{}, 1
	coOwned := ringtransfer.Signed(confidential2)
	coOwned.CoOwners = []*big.Int{coOwner}
	withCoOwner := ringtransfer.Hidden(anonymous2)
	withCoOwner.CoOwners = []*big.Int{coOwner}
	omitted := ringtransfer.Hidden(transfer.AnonymousShape{InputClass: 16, Outputs: 4, Withdrawals: 4})
	omitted.Omitted = 1
	withdrawing := ringtransfer.Hidden(anonymous2)
	withdrawing.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: 10}}
	withdrawing.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -10, Gross: 10}}
	replies := make([]byte, 97)
	for i := range replies {
		replies[i] = byte(0x17 ^ i)
	}
	ringtest.PinVector(t, "audit/transfer_statement_v3.json", map[string]any{
		"description": "Honest statements of the Go transfer fixtures, each solves its key, with every preimage of a chain or digest position. Confidential family 41 + N elements: head(12), in_proof, delegate, exempt, approval_required, output_count, output_chain, output_ciphertext_chain, recipient_key_chain, input_count, exits_bitmap, private_tx_hash, sender, signer_count, signer_chain, policy_hash, own_root, curator_root, recipient * N, (asset, net, gross) * 3, withdrawal_hash, length, version. Anonymous family 45 elements: head(12), exempt, approval_required, output_count, output_chain, output_ciphertext_chain, recipient_body_chain, recipient_tag_chain, change_bitmap, sender_bundle_digest, input_count, exits_bitmap, private_tx_hash, party * 3, signer_count, signer_chain, policy_hash, own_root, curator_root, (asset, net, gross) * 3, withdrawal_hash, reply_digest, length, version. outputs lists the published slots, chains zero fill to output_capacity. A delivered slot's ciphertext is body, an anonymous or exit slot's is record, recipient_body and tag are absent on change and exit. recipient_tag_chain is HashChain4(tag_0 .. tag_(N-1), sender_bundle_tag) with zero on change, exit and past output_count. signer_chain is HashChain4(signers, zeros up to signer_slots), zero on an empty run. withdrawal_hash is HashChain4(CRPW, count, owner, asset, amount per leg). envelope_digest, sender_bundle_digest and reply_digest are Poseidon(u32 len, HashChain4(pack_left31(bytes))), reply_digest zero without replies. public_input_hash = HashChain4(elements). Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases": []transferStatementVector{
			confidentialCase(t, "signer", ringtransfer.Signed(confidential2)),
			confidentialCase(t, "signer_two_owners", coOwned),
			confidentialCase(t, "in_proof", onRail(ringtransfer.InProof)),
			confidentialCase(t, "authority", onRail(ringtransfer.Delegate)),
			confidentialCase(t, "signer_compact", compact),
			anonymousCase(t, "commitment", ringtransfer.Hidden(anonymous2), nil),
			anonymousCase(t, "commitment_co_owner", withCoOwner, nil),
			anonymousCase(t, "entry", ringtransfer.Hidden(entry2), nil),
			anonymousCase(t, "commitment_compact", omitted, nil),
			anonymousCase(t, "commitment_withdrawal", withdrawing, nil),
			anonymousCase(t, "commitment_reply", ringtransfer.Hidden(anonymous2), replies),
		},
	})
}

type signerSetCase struct {
	Name    string   `json:"name"`
	Slots   int      `json:"slots"`
	Signers []string `json:"signers"`
	Chain   string   `json:"signer_chain"`
}

// Every language rebuilds one chain per run, an empty run reads zero at any slot count.
func TestSignerSetVector(t *testing.T) {
	run := func(name string, slots int, signers ...*big.Int) signerSetCase {
		return signerSetCase{Name: name, Slots: slots, Signers: append([]string{}, hexes(signers)...), Chain: ringtest.FieldHex(ringaudit.SignerChain(t, signers, slots))}
	}
	cases := []signerSetCase{
		run("empty on a confidential key", 24),
		run("empty on an entry key", 0),
		run("one owner", 24, coOwner),
		run("two owners in run order", 24, coOwner, otherCoOwner),
		run("the same owners reordered", 24, otherCoOwner, coOwner),
		run("one owner on a smaller class", 5, coOwner),
	}
	circuit, err := transfer.NewConfidentialTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	w := ringtransfer.Signed(confidential2)
	w.CoOwners = []*big.Int{coOwner}
	b := w.Build(t)
	ringkey.Bind(t, circuit, b.Circuit)
	ringtest.PinVector(t, "audit/signer_set.json", map[string]any{
		"description": "signer_chain over the SPP owner signer run. A count of zero binds chain zero and every signer slot zero on every rail, else HashChain4(identity_0 .. identity_{count-1}, 0 .. 0 up to slots). Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"cases":       cases,
	})
}

type poolCapacity struct {
	Key     string `json:"key"`
	Own     int    `json:"own"`
	Curator int    `json:"curator"`
}

// The pools a key compiles are the formula Rust's RingCircuit::record_pools keeps.
func TestPoolCapacityVector(t *testing.T) {
	var keys []poolCapacity
	for _, shape := range transfer.ConfidentialShapes {
		c, err := transfer.NewConfidentialTransferCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, poolCapacity{shape.String(), c.RecordPools().Own, c.RecordPools().Curator})
	}
	for _, shape := range append(transfer.AnonymousShapes[:], transfer.EntryShapes[:]...) {
		c, err := transfer.NewAnonymousTransferCircuit(shape)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, poolCapacity{shape.String(), c.RecordPools().Own, c.RecordPools().Curator})
	}
	ringtest.PinVector(t, "policy/pool_capacity.json", map[string]any{
		"description": "The record pools each transfer key compiles. distinct = Q + 2 * N + w, own = distinct + max(min(w, 3), 3), curator = distinct + min(w, 3), Q 4 on confidential and commitment keys and 1 on entry keys. Produced by prover/circuits/transfer/statement_vector_test.go with WRITE_AUDIT_VECTORS=1.",
		"keys":        keys,
	})
}
