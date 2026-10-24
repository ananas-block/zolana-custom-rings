package shared_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type ringTagVectors struct {
	Constants struct {
		EpochSlots  int `json:"epoch_slots"`
		JInbox      int `json:"j_inbox"`
		JPair       int `json:"j_pair"`
		KPairEpochs int `json:"k_pair_epochs"`
		TagLen      int `json:"tag_len"`
		BodyLen     int `json:"body_len"`
	} `json:"constants"`
	RingProgramAddress string            `json:"ring_program_id"`
	RingProgramID      string            `json:"ring_id"`
	ViewingPk          string            `json:"viewing_pk"`
	InboxKey           string            `json:"inbox_key"`
	InboxTags          []streamTagVector `json:"inbox_tags"`
	FirstContactSecret string            `json:"first_contact_secret"`
	PairKey            string            `json:"pair_key"`
	PairTags           []streamTagVector `json:"pair_tags"`
	Low128             []struct {
		Value string `json:"value"`
		Tag   string `json:"tag"`
	} `json:"low128"`
}

type streamTagVector struct {
	Epoch uint64 `json:"epoch"`
	Index int    `json:"index"`
	Tag   string `json:"tag"`
}

type ringTagsCircuit struct {
	RingProgramAddress [32]frontend.Variable
	RingProgramID      frontend.Variable
	ViewingPk          [33]frontend.Variable
	InboxKey           frontend.Variable
	InboxTags          []streamTagWires
	FirstContactSecret frontend.Variable
	PairKey            frontend.Variable
	PairTags           []streamTagWires
	Low128             []low128Wires
}

type streamTagWires struct{ Epoch, Index, Tag frontend.Variable }

type low128Wires struct{ Value, Tag frontend.Variable }

func (c *ringTagsCircuit) Define(api frontend.API) error {
	rc := rangecheck.New(api)
	api.AssertIsEqual(gadget.HashBytes(api, c.RingProgramAddress[:]), c.RingProgramID)
	inboxKey := shared.InboxKey(api, c.RingProgramID, [2]frontend.Variable(gadget.PackBytesBE(api, c.ViewingPk[:])))
	api.AssertIsEqual(inboxKey, c.InboxKey)
	for _, tag := range c.InboxTags {
		api.AssertIsEqual(shared.TagField(api, rc, shared.InboxTagDigest(api, inboxKey, tag.Epoch, tag.Index)), tag.Tag)
	}
	pairKey := shared.PairKey(api, c.FirstContactSecret)
	api.AssertIsEqual(pairKey, c.PairKey)
	for _, tag := range c.PairTags {
		api.AssertIsEqual(shared.TagField(api, rc, shared.PairTagDigest(api, pairKey, tag.Epoch, tag.Index)), tag.Tag)
	}
	for _, low := range c.Low128 {
		api.AssertIsEqual(shared.TagField(api, rc, low.Value), low.Tag)
	}
	return nil
}

func TestRingTagsMatchRustVectors(t *testing.T) {
	var vectors ringTagVectors
	ringtest.ReadVector(t, "ring-tags.json", &vectors)
	constants := vectors.Constants
	if constants.EpochSlots != shared.EpochSlots || constants.JInbox != shared.JInbox || constants.JPair != shared.JPair ||
		constants.KPairEpochs != shared.KPairEpochs || constants.TagLen != shared.TagLen || constants.BodyLen != shared.BodyLen {
		t.Fatalf("stream constants drifted from the Rust vector, got %+v", constants)
	}
	witness := &ringTagsCircuit{
		RingProgramID:      ringtest.VectorField(t, vectors.RingProgramID),
		InboxKey:           ringtest.VectorField(t, vectors.InboxKey),
		InboxTags:          streamTags(t, vectors.InboxTags),
		FirstContactSecret: ringtest.VectorField(t, vectors.FirstContactSecret),
		PairKey:            ringtest.VectorField(t, vectors.PairKey),
		PairTags:           streamTags(t, vectors.PairTags),
	}
	copy(witness.RingProgramAddress[:], ringtest.VectorWires(t, vectors.RingProgramAddress, 32))
	copy(witness.ViewingPk[:], ringtest.VectorWires(t, vectors.ViewingPk, 33))
	for _, low := range vectors.Low128 {
		witness.Low128 = append(witness.Low128, low128Wires{Value: ringtest.VectorField(t, low.Value), Tag: tagField(t, low.Tag)})
	}
	circuit := &ringTagsCircuit{
		InboxTags: make([]streamTagWires, len(witness.InboxTags)),
		PairTags:  make([]streamTagWires, len(witness.PairTags)),
		Low128:    make([]low128Wires, len(witness.Low128)),
	}
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring tag vector rejected, %v", err)
	}
	witness.PairTags[0].Index = vectors.PairTags[0].Index + 1
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("pair tag accepted under another stream index")
	}
}

func tagField(t *testing.T, tag string) *big.Int {
	t.Helper()
	return new(big.Int).SetBytes(ringtest.VectorBytes(t, tag, shared.TagLen))
}

func streamTags(t *testing.T, vectors []streamTagVector) []streamTagWires {
	t.Helper()
	wires := make([]streamTagWires, len(vectors))
	for i, tag := range vectors {
		wires[i] = streamTagWires{Epoch: tag.Epoch, Index: tag.Index, Tag: tagField(t, tag.Tag)}
	}
	return wires
}

type ringSecretVectors struct {
	TxViewingSk        string `json:"tx_viewing_secret"`
	TxViewingPk        string `json:"tx_viewing_pk"`
	RecipientViewingPk string `json:"recipient_viewing_pk"`
	Agreement          string `json:"agreement"`
	Salt               string `json:"salt"`
	FirstNullifier     string `json:"first_nullifier"`
	BlindingSeed       string `json:"blinding_seed"`
	OutputBlindingSeed string `json:"output_blinding_seed"`
	Outputs            []struct {
		OutputIndex         int    `json:"output_index"`
		DeliveredSlotSecret string `json:"delivered_slot_secret"`
		Tag                 string `json:"tag"`
		AnonymousRingData   string `json:"anonymous_ring_data"`
		Blinding            string `json:"blinding"`
	} `json:"outputs"`
	SenderKey             string `json:"sender_key"`
	SenderPkHash          string `json:"sender_pk_hash"`
	PrivateTxBlinding     string `json:"private_tx_blinding"`
	SenderCommitment      string `json:"sender_commitment"`
	DepositBlindingSecret string `json:"deposit_blinding_secret"`
	DepositBlinding       string `json:"deposit_blinding"`
}

type ringSecretsCircuit struct {
	OutputIndexes         []int `gnark:"-"`
	TxViewingSk           [32]frontend.Variable
	TxViewingPk           [33]frontend.Variable
	RecipientViewingPk    [33]frontend.Variable
	Agreement             [32]frontend.Variable
	Salt                  [16]frontend.Variable
	FirstNullifier        frontend.Variable
	BlindingSeed          frontend.Variable
	OutputBlindingSeed    frontend.Variable
	Outputs               []ringSecretWires
	SenderKey             [32]frontend.Variable
	SenderPkHash          frontend.Variable
	PrivateTxBlinding     frontend.Variable
	SenderCommitment      frontend.Variable
	DepositBlindingSecret frontend.Variable
	DepositBlinding       frontend.Variable
}

type ringSecretWires struct {
	DeliveredSlotSecret, Tag, AnonymousRingData, Blinding frontend.Variable
}

func (c *ringSecretsCircuit) Define(api frontend.API) error {
	salt := gadget.PackBytesBE(api, c.Salt[:])[0]
	seed := shared.BlindingSeed(api, [2]frontend.Variable(gadget.PackBytesBE(api, c.TxViewingSk[:])), salt)
	api.AssertIsEqual(seed, c.BlindingSeed)
	outputSeed := transaction.DeriveOutputBlindingSeed(api, c.FirstNullifier, seed)
	api.AssertIsEqual(outputSeed, c.OutputBlindingSeed)
	for k, out := range c.Outputs {
		i := c.OutputIndexes[k]
		delivered := shared.DeliveredSlot{
			Agreement:      [2]frontend.Variable(gadget.PackBytesBE(api, c.Agreement[:])),
			TxPk:           [2]frontend.Variable(gadget.PackBytesBE(api, c.TxViewingPk[:])),
			Recipient:      [2]frontend.Variable(gadget.PackBytesBE(api, c.RecipientViewingPk[:])),
			Salt:           salt,
			OutputIndex:    i,
			FirstNullifier: c.FirstNullifier,
		}.Secret(api)
		api.AssertIsEqual(delivered, out.DeliveredSlotSecret)
		api.AssertIsEqual(shared.AnonymousRingData(api, delivered, out.Tag), out.AnonymousRingData)
		api.AssertIsEqual(transaction.DeriveOutputBlinding(api, c.FirstNullifier, outputSeed, i), out.Blinding)
	}
	senderPkHash := gadget.SolanaOwnerIdentity(api, c.SenderKey)
	api.AssertIsEqual(senderPkHash, c.SenderPkHash)
	privateTxBlinding := transaction.DerivePrivateTxBlinding(api, c.FirstNullifier, seed)
	api.AssertIsEqual(privateTxBlinding, c.PrivateTxBlinding)
	api.AssertIsEqual(shared.SenderCommitment(api, senderPkHash, privateTxBlinding), c.SenderCommitment)
	api.AssertIsEqual(shared.DepositBlinding(api, c.DepositBlindingSecret), c.DepositBlinding)
	return nil
}

// The circuit gadgets rebuild every CRBS, TXOB and CRAT value of the Rust vector from tx_viewing_sk.
func TestRingSecretsMatchRustVectors(t *testing.T) {
	var vectors ringSecretVectors
	ringtest.ReadVector(t, "ring-secrets.json", &vectors)
	witness := &ringSecretsCircuit{
		FirstNullifier:        ringtest.VectorField(t, vectors.FirstNullifier),
		BlindingSeed:          ringtest.VectorField(t, vectors.BlindingSeed),
		OutputBlindingSeed:    ringtest.VectorField(t, vectors.OutputBlindingSeed),
		SenderPkHash:          ringtest.VectorField(t, vectors.SenderPkHash),
		PrivateTxBlinding:     ringtest.VectorField(t, vectors.PrivateTxBlinding),
		SenderCommitment:      ringtest.VectorField(t, vectors.SenderCommitment),
		DepositBlindingSecret: ringtest.VectorField(t, vectors.DepositBlindingSecret),
		DepositBlinding:       ringtest.VectorField(t, vectors.DepositBlinding),
	}
	copy(witness.TxViewingSk[:], ringtest.VectorWires(t, vectors.TxViewingSk, 32))
	copy(witness.TxViewingPk[:], ringtest.VectorWires(t, vectors.TxViewingPk, 33))
	copy(witness.RecipientViewingPk[:], ringtest.VectorWires(t, vectors.RecipientViewingPk, 33))
	copy(witness.Agreement[:], ringtest.VectorWires(t, vectors.Agreement, 32))
	copy(witness.Salt[:], ringtest.VectorWires(t, vectors.Salt, 16))
	copy(witness.SenderKey[:], ringtest.VectorWires(t, vectors.SenderKey, 32))
	for _, out := range vectors.Outputs {
		witness.OutputIndexes = append(witness.OutputIndexes, out.OutputIndex)
		witness.Outputs = append(witness.Outputs, ringSecretWires{
			DeliveredSlotSecret: ringtest.VectorField(t, out.DeliveredSlotSecret),
			Tag:                 tagField(t, out.Tag),
			AnonymousRingData:   ringtest.VectorField(t, out.AnonymousRingData),
			Blinding:            ringtest.VectorField(t, out.Blinding),
		})
	}
	circuit := &ringSecretsCircuit{OutputIndexes: witness.OutputIndexes, Outputs: make([]ringSecretWires, len(witness.Outputs))}
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("ring secret vector rejected, %v", err)
	}
	witness.Outputs[0].Tag = new(big.Int).Add(tagField(t, vectors.Outputs[0].Tag), big.NewInt(1))
	if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("anonymous ring data accepted under another tag")
	}
}
