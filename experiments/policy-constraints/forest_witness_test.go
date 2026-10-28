package policy

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

type forestExpected struct{ Member, Lists, Escrow, Mint frontend.Variable }
type forestRoleWitness struct {
	Pool     rolePool
	Expected []forestExpected
}
type forestRoleCircuit struct {
	Roles [4]forestRoleWitness
	Roots [2]frontend.Variable `gnark:",public"`
}
type forestFixtureShape struct {
	Participants, Assets, AssetHeight int
	LeafDomain                        int64
}

func (c *forestRoleCircuit) Define(api frontend.API) error {
	roots := make([]frontend.Variable, 4)
	for role, w := range c.Roles {
		pool, root := w.Pool.open(api, 1)
		roots[role] = root
		for i, expected := range w.Expected {
			actual := pool.resolve(api, recordQuery{active: 1, member: expected.Member, index: i})
			api.AssertIsEqual(api.FromBinary(actual.onList[:]...), expected.Lists)
			api.AssertIsEqual(actual.escrowKey, expected.Escrow)
			base := new(big.Int).Lsh(big.NewInt(1), 64)
			api.AssertIsEqual(api.Add(actual.mintPolicy.cosignAbove, api.Mul(base, actual.mintPolicy.cap), api.Mul(new(big.Int).Mul(base, base), actual.mintPolicy.threshold)), expected.Mint)
		}
	}
	for i := range c.Roots {
		root := gadgetHeader(api, roots[2*i], roots[2*i+1], c.Roles[2*i].Pool.Proof.Height, c.Roles[2*i+1].Pool.Proof.Height)
		api.AssertIsEqual(root, c.Roots[i])
	}
	return nil
}

func newRoleCircuit(shape forestFixtureShape) *forestRoleCircuit {
	c := &forestRoleCircuit{}
	for i := range c.Roles {
		count, height := shape.Participants, 10
		assets := i%2 == 1
		if assets {
			count, height = shape.Assets, shape.AssetHeight
		}
		c.Roles[i].Pool = newRolePool(count, height, assets)
		c.Roles[i].Pool.Subjects = make([]PoolSubject, count+1)
		c.Roles[i].Expected = make([]forestExpected, count+1)
	}
	return c
}

func forestFixture(t testing.TB, shape forestFixtureShape) *forestRoleCircuit {
	t.Helper()
	c := newRoleCircuit(shape)
	roots := make([]*big.Int, 4)
	for role := range c.Roles {
		w := &c.Roles[role]
		p := &w.Pool
		count := len(p.Records)
		start := 100
		if p.Assets {
			start = 1000
		}
		for i := range p.Records {
			next := new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))
			if i+1 < count {
				next = big.NewInt(int64(start + 2*i + 2))
			}
			r := registry.Record{Member: big.NewInt(int64(start + 2*i)), Next: next, Lists: 1, EscrowKey: 0, MintPolicy: 0, WithdrawalThreshold: 0}
			if p.Assets {
				r.MintPolicy = new(big.Int).Add(new(big.Int).Lsh(big.NewInt(int64(3+role)), 128), big.NewInt(int64(i+1)))
				r.WithdrawalThreshold = 7
			} else {
				r.EscrowKey = 10000 + 100*role + i
			}
			p.Records[i] = r
			p.Subjects[i] = PoolSubject{Member: r.Member, RecordIndex: i}
			w.Expected[i] = forestExpected{Member: r.Member, Lists: 1, Escrow: r.EscrowKey, Mint: r.MintPolicy}
		}
		absent := big.NewInt(int64(start + 1))
		p.Subjects[count] = PoolSubject{Member: absent, RecordIndex: 0}
		w.Expected[count] = forestExpected{Member: absent, Lists: 0, Escrow: 0, Mint: 0}
		domain := int64(1)
		if p.Assets {
			domain = 2
		}
		if shape.LeafDomain != 0 {
			domain = shape.LeafDomain
		}
		roots[role] = fillForestProof(t, p, domain)
	}
	for i := range c.Roots {
		c.Roots[i] = nativeForestHash(t, 3, roots[2*i], roots[2*i+1], big.NewInt(10), big.NewInt(int64(shape.AssetHeight)))
	}
	return c
}

func fillForestProof(t testing.TB, p *rolePool, domain int64) *big.Int {
	t.Helper()
	height := p.Proof.Height
	indices := make([]int, len(p.Records))
	levels := make([]map[int]*big.Int, height+1)
	levels[0] = map[int]*big.Int{}
	leaf := func(r registry.Record) *big.Int {
		values := []*big.Int{forestBig(r.Member), forestBig(r.Next), forestBig(r.Lists)}
		if p.Assets {
			values = append(values, forestBig(r.MintPolicy), forestBig(r.WithdrawalThreshold))
		} else {
			values = append(values, forestBig(r.EscrowKey))
		}
		return nativeForestHash(t, domain, values...)
	}
	levels[0][0] = leaf(registry.Record{Member: 0, Next: p.Records[0].Member, Lists: 0, EscrowKey: 0, MintPolicy: 0, WithdrawalThreshold: 0})
	for i, r := range p.Records {
		index := i + 1
		indices[i] = index
		levels[0][index] = leaf(r)
	}
	zeros := make([]*big.Int, height+1)
	zeros[0] = big.NewInt(0)
	get := func(level, index int) *big.Int {
		if v, ok := levels[level][index]; ok {
			return v
		}
		return zeros[level]
	}
	for level := 0; level < height; level++ {
		zeros[level+1] = nativeForestHash(t, 0, zeros[level], zeros[level], zeros[level], zeros[level])
		levels[level+1] = map[int]*big.Int{}
		for index := range levels[level] {
			parent := index / 4
			if _, done := levels[level+1][parent]; done {
				continue
			}
			levels[level+1][parent] = nativeForestHash(t, 0, get(level, 4*parent), get(level, 4*parent+1), get(level, 4*parent+2), get(level, 4*parent+3))
		}
	}
	lower := len(p.Proof.Paths[0].Siblings)
	for i := range p.Proof.Canopy {
		p.Proof.Canopy[i] = get(lower, i)
	}
	for i, index := range indices {
		p.Proof.Paths[i].Index = index
		for level := range p.Proof.Paths[i].Siblings {
			sibling := 0
			for child := 0; child < 4; child++ {
				if child != index%4 {
					p.Proof.Paths[i].Siblings[level][sibling] = get(level, index/4*4+child)
					sibling++
				}
			}
			index /= 4
		}
	}
	return get(height, 0)
}

func forestBig(value frontend.Variable) *big.Int {
	switch v := value.(type) {
	case *big.Int:
		return new(big.Int).Set(v)
	case int:
		return big.NewInt(int64(v))
	case int64:
		return big.NewInt(v)
	case uint64:
		return new(big.Int).SetUint64(v)
	default:
		panic(fmt.Sprintf("unsupported fixture value %T", value))
	}
}
func nativeForestHash(t testing.TB, domain int64, values ...*big.Int) *big.Int {
	t.Helper()
	v, err := poseidon.HashWithState(values, big.NewInt(domain))
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func solveForest(cs constraint.ConstraintSystem, c *forestRoleCircuit) error {
	w, err := frontend.NewWitness(c, ecc.BN254.ScalarField())
	if err != nil {
		return err
	}
	return cs.IsSolved(w)
}

func TestForestRoleWitnesses(t *testing.T) {
	for _, shape := range []forestFixtureShape{{Participants: 3, Assets: 3, AssetHeight: 1}, {Participants: 49, Assets: 3, AssetHeight: 1}, {Participants: 49, Assets: 19, AssetHeight: 5}} {
		t.Run(fmt.Sprintf("participants%d-assets%d-height%d", shape.Participants, shape.Assets, shape.AssetHeight), func(t *testing.T) {
			cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, newRoleCircuit(shape), frontend.WithCompressThreshold(300))
			if err != nil {
				t.Fatal(err)
			}
			if err = solveForest(cs, forestFixture(t, shape)); err != nil {
				t.Fatal(err)
			}
			t.Logf("compiled role witness solved with %d constraints", cs.GetNbConstraints())
			cases := map[string]func(*forestRoleCircuit){
				"own root":      func(c *forestRoleCircuit) { c.Roots[0] = 1 },
				"curator root":  func(c *forestRoleCircuit) { c.Roots[1] = 1 },
				"record lists":  func(c *forestRoleCircuit) { c.Roles[0].Pool.Records[0].Lists = 0 },
				"record escrow": func(c *forestRoleCircuit) { c.Roles[0].Pool.Records[0].EscrowKey = 0 },
				"asset policy":  func(c *forestRoleCircuit) { c.Roles[1].Pool.Records[0].MintPolicy = 0 },
				"subject index": func(c *forestRoleCircuit) { c.Roles[0].Pool.Subjects[0].RecordIndex = 1 },
				"subject key":   func(c *forestRoleCircuit) { c.Roles[0].Pool.Subjects[0].Member = 104 },
				"absent existing key": func(c *forestRoleCircuit) {
					i := len(c.Roles[0].Pool.Subjects) - 1
					c.Roles[0].Pool.Subjects[i].Member = 102
					c.Roles[0].Expected[i].Member = 102
				},
				"canonical index": func(c *forestRoleCircuit) { c.Roles[0].Pool.Proof.Paths[0].Index = 1 + (1 << 20) },
				"negative index":  func(c *forestRoleCircuit) { c.Roles[0].Pool.Proof.Paths[0].Index = -1 },
				"path sibling":    func(c *forestRoleCircuit) { c.Roles[0].Pool.Proof.Paths[0].Siblings[0][0] = 1 },
				"canopy node":     func(c *forestRoleCircuit) { c.Roles[0].Pool.Proof.Canopy[0] = 1 },
				"header height": func(c *forestRoleCircuit) {
					p := &c.Roles[0].Pool
					a := &c.Roles[1].Pool
					pr := fillForestProof(t, p, 1)
					ar := fillForestProof(t, a, 2)
					c.Roots[0] = nativeForestHash(t, 3, pr, ar, big.NewInt(9), big.NewInt(int64(shape.AssetHeight)))
				},
				"header domain": func(c *forestRoleCircuit) {
					p := &c.Roles[0].Pool
					a := &c.Roles[1].Pool
					pr := fillForestProof(t, p, 1)
					ar := fillForestProof(t, a, 2)
					c.Roots[0] = nativeForestHash(t, 4, pr, ar, big.NewInt(10), big.NewInt(int64(shape.AssetHeight)))
				},
			}
			for name, mutate := range cases {
				t.Run(name, func(t *testing.T) {
					bad := forestFixture(t, shape)
					mutate(bad)
					if err := solveForest(cs, bad); err == nil {
						t.Fatal("forged forest accepted")
					}
				})
			}
			t.Run("leaf domain", func(t *testing.T) {
				badShape := shape
				badShape.LeafDomain = 4
				if err := solveForest(cs, forestFixture(t, badShape)); err == nil {
					t.Fatal("wrong leaf domain accepted")
				}
			})
		})
	}
}
