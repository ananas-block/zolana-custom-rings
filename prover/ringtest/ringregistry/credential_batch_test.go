package ringregistry_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

func credentialBatch(t testing.TB) *registry.PrivateApplyRecordsCircuit {
	t.Helper()
	return ringregistry.PrivateBatch(t, 2, ringregistry.PrivateBlockBit)
}

func TestPrivateWriteBatchBindsClassification(t *testing.T) {
	requireCredentialSolved(t, credentialBatch(t))
	for _, tc := range []struct {
		name   string
		mutate func(*registry.PrivateApplyRecordsCircuit)
	}{
		{"credential bit past count", func(c *registry.PrivateApplyRecordsCircuit) {
			c.CredentialWrites = 3
			c.Writes[1], c.Credentials[1] = c.Writes[0], c.Credentials[0]
		}},
		{"credential bit past capacity", func(c *registry.PrivateApplyRecordsCircuit) { c.CredentialWrites = 4 }},
		{"substituted write member", func(c *registry.PrivateApplyRecordsCircuit) { c.Writes[0].Entry.Member = 2 }},
		{"substituted credential member", func(c *registry.PrivateApplyRecordsCircuit) { c.Credentials[0].Member = 103 }},
		{"wrong address checkpoint", func(c *registry.PrivateApplyRecordsCircuit) { c.AddressRoot = 19 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := credentialBatch(t)
			tc.mutate(c)
			ringregistry.BindPrivateBatch(t, c)
			requireCredentialRefused(t, c, "registry.(*PrivateApplyRecordsCircuit).Define")
		})
	}
}

// Each private list takes the credential path, a substituted salt fails the binding.
func TestEveryPrivateListBindsItsSalt(t *testing.T) {
	for _, mask := range []int64{ringregistry.PrivateBlockBit, ringregistry.PrivateAllowBit, ringregistry.PrivateFrozenBit} {
		requireCredentialSolved(t, ringregistry.PrivateBatch(t, 2, mask))
		c := ringregistry.PrivateBatch(t, 2, mask)
		c.Credentials[0].ListSalt = 0x1234
		requireCredentialRefused(t, c, "registry.CredentialWrite.Assert")
	}
}

func TestPrivateWriteClassificationRejectsPublicMask(t *testing.T) {
	requireCredentialRefused(t, ringregistry.PrivateBatch(t, 2, ringregistry.AllowBit), "registry.(*PrivateApplyRecordsCircuit).Define")
}

func TestPrivateWriteValueCannotSetUnmaskedBits(t *testing.T) {
	c := ringregistry.PrivateBatch(t, 2, ringregistry.PrivateBlockBit|ringregistry.AllowBit)
	c.Writes[0].Entry.Mask = ringregistry.PrivateBlockBit
	entry := ringregistry.Entry{
		Member: ringtest.AsBigInt(c.Writes[0].Entry.Member), Mask: big.NewInt(ringregistry.PrivateBlockBit),
		Value: big.NewInt(ringregistry.PrivateBlockBit | ringregistry.AllowBit),
	}
	c.ChainEnd = ringtest.MustPoseidonHash(t, ringtest.AsBigInt(c.ChainStart), entry.Hash(t))
	ringregistry.BindPrivateBatch(t, c)
	requireCredentialRefused(t, c, "registry.RecordWriteProofInput.apply")
}

// A private key covers at least one private owner write, a public batch has its own key.
func TestPrivateKeyRefusesAnEmptyCheckpoint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*registry.PrivateApplyRecordsCircuit)
	}{
		{"bitmap", func(c *registry.PrivateApplyRecordsCircuit) {
			c.CredentialWrites = 0
			c.Credentials[0] = ringregistry.ZeroCredentialWrite()
		}},
		{"ring", func(c *registry.PrivateApplyRecordsCircuit) { c.PrivateRingID = 0 }},
		{"credential owner", func(c *registry.PrivateApplyRecordsCircuit) { c.CredentialOwner = 0 }},
		{"address root", func(c *registry.PrivateApplyRecordsCircuit) { c.AddressRoot = 0 }},
		{"public batch with zero credential fields", func(c *registry.PrivateApplyRecordsCircuit) {
			c.CredentialWrites, c.PrivateRingID, c.CredentialOwner, c.AddressRoot = 0, 0, 0, 0
			for i := range c.StateRoots {
				c.StateRoots[i] = [2]frontend.Variable{0, 0}
				c.Credentials[i] = ringregistry.ZeroCredentialWrite()
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := credentialBatch(t)
			tc.mutate(c)
			ringregistry.BindPrivateBatch(t, c)
			requireCredentialRefused(t, c, "registry.(*PrivateApplyRecordsCircuit).credentialBits")
		})
	}
}
