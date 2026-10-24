// Package ringdeposit is the host twin of the ring deposit circuit for the Go tests.
package ringdeposit

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/shared"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// RingMode mirrors RingMode in program-libs/interface/src/state.rs, the flags DepositPublicInput binds follow it.
type RingMode int

const (
	ModeOff RingMode = iota
	ModeRegistry
	ModeAnonymous
)

type Deposit struct {
	Circuit *circuits.DepositCircuit
}

// Build deposits count owners under the CRDB blinding, escrowed on ModeRegistry and disclosing their keys on ModeAnonymous.
func Build(t testing.TB, count int, mode RingMode) *Deposit {
	t.Helper()
	return BuildBlinded(t, count, mode, ringprotocol.DepositBlinding)
}

// BuildBlinded is Build with blindingOf deriving the blinding every commitment and opening carries.
func BuildBlinded(t testing.TB, count int, mode RingMode, blindingOf func(testing.TB, *big.Int) *big.Int) *Deposit {
	t.Helper()
	anonymous, escrow := mode == ModeAnonymous, mode == ModeRegistry
	keys, registry := ringaudit.DefaultKeys(t), ringregistry.New(t)
	c := &circuits.DepositCircuit{
		ContextHash: big.NewInt(0xabcdef), Count: count, Anonymous: ringtest.Bit(anonymous), KeyEscrow: ringtest.Bit(escrow), MemberRegistryRoot: 0,
	}
	eph, auditor := keys.EphSk(), keys.AuditorPk()
	ringtest.SetBytes(c.EphSk[:], eph[:])
	ringtest.SetBytes(c.AuditorPk[:], auditor[:])
	plaintext := make([]byte, circuits.MaxDeposits*circuits.DepositOpeningBytes)
	commitments := make([]*big.Int, circuits.MaxDeposits)
	for i := range circuits.MaxDeposits {
		var key [32]byte
		ownerPkHash, nullifierPk, secret, ctHash := big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < count {
			ownerPkHash = big.NewInt(int64(11 + i))
			if anonymous {
				for j := range key {
					key[j] = byte(i + j + 1)
				}
				ownerPkHash = ringtest.MustSolanaPkField(t, key)
			}
			nullifierPk = spptest.MustNullifierPk(t, big.NewInt(int64(51+i)))
			secret = big.NewInt(int64(91 + i))
			if escrow {
				ctHash = big.NewInt(int64(0xc0 + i))
				registry.Apply(t, ringregistry.Entry{
					Member: ownerPkHash, Mask: big.NewInt(ringregistry.EscrowBit), Value: big.NewInt(ringregistry.EscrowBit),
					EscrowKey: ringregistry.EscrowKey(t, nullifierPk, ctHash),
				})
			}
		}
		c.OwnerPkHashes[i], c.NullifierPks[i], c.BlindingSecrets[i], c.CtHashes[i] = ownerPkHash, nullifierPk, secret, ctHash
		ringtest.SetBytes(c.OwnerKeys[i][:], key[:])
		owner := spptest.MustOwnerHash(t, ownerPkHash, nullifierPk)
		blinding := blindingOf(t, secret)
		commitments[i] = ringtest.MustPoseidonHash(t, owner, blinding)
		opening := plaintext[i*circuits.DepositOpeningBytes : (i+1)*circuits.DepositOpeningBytes]
		owner.FillBytes(opening[:32])
		blinding.FillBytes(opening[32:64])
		copy(opening[64:], key[:])
	}
	for i := range circuits.MaxDeposits {
		c.Members[i] = ringregistry.UnreadRecordWires()
		if escrow {
			c.Members[i] = registry.Opening(ringtest.AsBigInt(c.OwnerPkHashes[i])).RecordWires()
		}
	}
	if escrow {
		c.MemberRegistryRoot = registry.Root()
	}
	ciphertext := keys.EnvelopeCiphertext(t, plaintext, shared.DepositEncInfo)
	sealed := keys.Sealed(t, ciphertext)
	// Ordered as DepositPublicInput::elements.
	chain := []*big.Int{big.NewInt(shared.DepositStatementDomain), ringtest.AsBigInt(c.ContextHash), big.NewInt(int64(count)), ringtest.AsBigInt(c.Anonymous)}
	for i := range circuits.MaxDeposits {
		if i >= count {
			chain = append(chain, big.NewInt(0), big.NewInt(0))
			continue
		}
		chain = append(chain, commitments[i], ringtest.HashBytes(t, ciphertext[i*circuits.DepositOpeningBytes:(i+1)*circuits.DepositOpeningBytes]))
	}
	chain = append(chain, sealed.AuditorLo, sealed.AuditorHi, sealed.EphLo, sealed.EphHi, ringtest.AsBigInt(c.KeyEscrow), ringtest.AsBigInt(c.MemberRegistryRoot))
	c.PublicInputHash = spptest.MustHashChain(t, chain)
	return &Deposit{Circuit: c}
}
