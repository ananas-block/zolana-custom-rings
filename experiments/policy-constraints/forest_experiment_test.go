package policy

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/selector"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

type forestPath struct {
	Index    frontend.Variable
	Siblings [][3]frontend.Variable
}
type forestProof struct {
	Canopy []frontend.Variable
	Paths  []forestPath
	Height int `gnark:"-"`
}
type rolePool struct {
	Records  []registry.Record
	Subjects []PoolSubject
	Proof    forestProof
	Assets   bool `gnark:"-"`
}
type forestWitness struct {
	OwnParticipants, OwnAssets         rolePool
	CuratorParticipants, CuratorAssets []rolePool
	SenderEntry                        PoolEntry
	OwnerEntries, AssetEntries         []PoolEntry
	PublicAssetEntries                 [3]frontend.Variable
}
type forestCircuit struct {
	MemberPolicyValues
	PolicyInputs
	Forest forestWitness
}
type forestResolver struct {
	policy                                                         *PolicyInputs
	witness                                                        *forestWitness
	ownParticipants, ownAssets, curatorParticipants, curatorAssets subjectPool
}

func newForestProof(count, height int) forestProof {
	if count < 1 || height < 1 || height > 10 || count > 1<<(2*height) {
		panic("invalid proof shape")
	}
	width, levels := 1, 0
	for width < count {
		width *= 4
		levels++
	}
	p := forestProof{Canopy: make([]frontend.Variable, width), Paths: make([]forestPath, count), Height: height}
	for i := range p.Paths {
		p.Paths[i].Siblings = make([][3]frontend.Variable, height-levels)
	}
	return p
}
func newRolePool(count, height int, assets bool) rolePool {
	return rolePool{Records: make([]registry.Record, count), Subjects: make([]PoolSubject, count), Proof: newForestProof(count, height), Assets: assets}
}
func newForest(shape MemberShape, assetCount, participantHeight, assetHeight int) *forestCircuit {
	c, err := NewMemberPolicyCircuitWith(shape)
	if err != nil {
		panic(err)
	}
	n := shape.Outputs + shape.Withdrawals
	w := forestWitness{OwnParticipants: newRolePool(n+1, participantHeight, false), OwnAssets: newRolePool(assetCount, assetHeight, true), SenderEntry: newPoolEntry(shape.OwnOnly), OwnerEntries: make([]PoolEntry, n), AssetEntries: make([]PoolEntry, n)}
	for i := range w.OwnerEntries {
		w.OwnerEntries[i] = newPoolEntry(shape.OwnOnly)
		w.AssetEntries[i] = newPoolEntry(shape.OwnOnly)
	}
	if !shape.OwnOnly {
		w.CuratorParticipants = []rolePool{newRolePool(n+1, participantHeight, false)}
		w.CuratorAssets = []rolePool{newRolePool(assetCount, assetHeight, true)}
	}
	return &forestCircuit{PolicyInputs: c.PolicyInputs, Forest: w}
}
func (c *forestCircuit) Define(api frontend.API) error {
	legacy := MemberPolicyCircuit{MemberPolicyValues: c.MemberPolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return legacy.define(api, &forestResolver{policy: &c.PolicyInputs, witness: &c.Forest}, 3)
}

func (p forestProof) root(api frontend.API, leaves []frontend.Variable) frontend.Variable {
	nodes := p.Canopy
	for len(nodes) > 1 {
		parents := make([]frontend.Variable, len(nodes)/4)
		for i := range parents {
			parents[i] = gadget.PoseidonHash(api, nodes[4*i:4*i+4])
		}
		nodes = parents
	}
	var table logderivlookup.Table
	if len(p.Canopy) > 16 {
		table = logderivlookup.New(api)
		for _, node := range p.Canopy {
			table.Insert(node)
		}
	}
	for i, path := range p.Paths {
		bits := api.ToBinary(path.Index, 2*p.Height)
		node := leaves[i]
		for level, siblings := range path.Siblings {
			b0, b1 := bits[2*level], bits[2*level+1]
			three := api.Mul(b0, b1)
			one := api.Sub(b0, three)
			two := api.Sub(b1, three)
			zero := api.Sub(api.Sub(1, b0), two)
			children := []frontend.Variable{api.Select(zero, node, siblings[0]), api.Select(zero, siblings[0], api.Select(one, node, siblings[1])), api.Select(three, siblings[2], api.Select(two, node, siblings[1])), api.Select(three, node, siblings[2])}
			node = gadget.PoseidonHash(api, children)
		}
		indexBits := bits[2*len(path.Siblings):]
		if table == nil {
			api.AssertIsEqual(selector.BinaryMux(api, indexBits, p.Canopy), node)
		} else {
			api.AssertIsEqual(table.Lookup(api.FromBinary(indexBits...))[0], node)
		}
	}
	return nodes[0]
}

func (p rolePool) open(api frontend.API, active frontend.Variable) (subjectPool, frontend.Variable) {
	api.AssertIsBoolean(active)
	pool := recordPool{active: active, table: lookup.New(api, 6+NSources)}
	leaves := make([]frontend.Variable, len(p.Records))
	for i, r := range p.Records {
		bits := api.ToBinary(r.Lists, registry.ListBits)
		var escrow frontend.Variable = 0
		mint := mintPolicyWires{threshold: 0, cap: 0, cosignAbove: 0}
		if p.Assets {
			leaves[i] = gadget.PoseidonHashWithState(api, []frontend.Variable{r.Member, r.Next, r.Lists, r.MintPolicy, r.WithdrawalThreshold}, 2)
			mint = decodePooledMintPolicy(api, r.MintPolicy)
		} else {
			leaves[i] = gadget.PoseidonHashWithState(api, []frontend.Variable{r.Member, r.Next, r.Lists, r.EscrowKey}, 1)
			escrow = r.EscrowKey
		}
		row := []frontend.Variable{r.Member, r.Next, escrow, mint.threshold, mint.cap, mint.cosignAbove}
		pool.table.Insert(append(row, bits[:NSources]...))
	}
	return openSubjectPool(api, pool, p.Subjects), p.Proof.root(api, leaves)
}
func (r *forestResolver) resolveSubjects(api frontend.API, t tableView, sender frontend.Variable, outputs []utxoView) (subjects, error) {
	w := r.witness
	p := r.policy
	var ownP, ownA, curP, curA frontend.Variable
	r.ownParticipants, ownP = w.OwnParticipants.open(api, 1)
	r.ownAssets, ownA = w.OwnAssets.open(api, 1)
	header := func(pr, ar frontend.Variable, ph, ah int) frontend.Variable { return gadgetHeader(api, pr, ar, ph, ah) }
	api.AssertIsEqual(header(ownP, ownA, w.OwnParticipants.Proof.Height, w.OwnAssets.Proof.Height), p.OwnRoot)
	if !p.OwnOnly {
		r.curatorParticipants, curP = w.CuratorParticipants[0].open(api, t.sources.anyForeign)
		r.curatorAssets, curA = w.CuratorAssets[0].open(api, t.sources.anyForeign)
		api.AssertIsEqual(api.Mul(t.sources.anyForeign, api.Sub(header(curP, curA, w.CuratorParticipants[0].Proof.Height, w.CuratorAssets[0].Proof.Height), p.CuratorRoot)), 0)
	}
	s := subjects{owners: make([]subjectView, len(outputs)), assets: make([]subjectView, len(outputs)), mintPolicies: make([]mintPolicyWires, len(outputs))}
	s.sender, _ = r.resolve(api, t.sources, w.SenderEntry, 1, sender, false)
	for i, out := range outputs {
		s.owners[i], _ = r.resolve(api, t.sources, w.OwnerEntries[i], out.utxo, out.ownerPkHash, false)
		s.assets[i], s.mintPolicies[i] = r.resolve(api, t.sources, w.AssetEntries[i], out.utxo, out.asset, true)
	}
	return s, nil
}
func (r *forestResolver) resolve(api frontend.API, sources sourceView, entry PoolEntry, active, member frontend.Variable, assets bool) (subjectView, mintPolicyWires) {
	ownPool, curPool := r.ownParticipants, r.curatorParticipants
	if assets {
		ownPool, curPool = r.ownAssets, r.curatorAssets
	}
	own := ownPool.resolve(api, recordQuery{active: active, member: member, index: entry.Own})
	view := subjectView{onList: own.onList, escrowKey: own.escrowKey}
	if !r.policy.OwnOnly {
		curator := curPool.resolve(api, recordQuery{active: api.Mul(active, sources.anyForeign), member: member, index: entry.Curator[0]})
		for i, value := range curator.onList {
			view.onList[i] = api.Select(sources.foreign[i], value, own.onList[i])
		}
	}
	return view, own.mintPolicy
}
func (r *forestResolver) resolvePublicAsset(api frontend.API, active, asset frontend.Variable, index int) mintPolicyWires {
	return r.ownAssets.resolve(api, recordQuery{active: active, member: asset, index: r.witness.PublicAssetEntries[index]}).mintPolicy
}

type forestDelegateCircuit struct {
	DelegatePolicyValues
	PolicyInputs
	Forest forestWitness
}

func (c *forestDelegateCircuit) Define(api frontend.API) error {
	legacy := DelegatePolicyCircuit{DelegatePolicyValues: c.DelegatePolicyValues, Policy: Policy{PolicyInputs: c.PolicyInputs}}
	return legacy.define(api, &forestResolver{policy: &c.PolicyInputs, witness: &c.Forest}, 3)
}

type forestCount struct {
	Circuit           string  `json:"circuit"`
	OwnOnly           bool    `json:"own_only"`
	Participants      int     `json:"participants"`
	Assets            int     `json:"assets"`
	ParticipantHeight int     `json:"participant_height"`
	AssetHeight       int     `json:"asset_height"`
	Baseline          int     `json:"baseline_v2_constraints"`
	Constraints       int     `json:"forest_constraints"`
	Savings           float64 `json:"savings_percent"`
}

func TestForestConstraintMatrix(t *testing.T) {
	var rows []forestCount
	compile := func(c frontend.Circuit) int {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		return cs.GetNbConstraints()
	}
	for _, own := range []bool{true, false} {
		for _, name := range []string{"member2", "member16w32", "delegate2", "delegate4"} {
			shape := MemberShape{Outputs: 2, OwnOnly: own}
			if name == "member16w32" {
				shape.Outputs = 16
				shape.Withdrawals = 32
			}
			if name == "delegate4" {
				shape.Outputs = 4
			}
			var baseline int
			if name == "delegate2" || name == "delegate4" {
				c, err := NewDelegatePolicyCircuitWith(DelegateShape{Shape: transaction.Shape{NInputs: shape.Outputs, NOutputs: shape.Outputs}, OwnOnly: own})
				if err != nil {
					t.Fatal(err)
				}
				baseline = compile(c)
			} else {
				c, err := NewMemberPolicyCircuitWith(shape)
				if err != nil {
					t.Fatal(err)
				}
				baseline = compile(c)
			}
			assetCounts := []int{1, 3}
			if name == "member16w32" {
				assetCounts = append(assetCounts, 19)
			}
			for _, assets := range assetCounts {
				heights := []int{1, 5, 10}
				if assets == 19 {
					heights = []int{3, 5, 10}
				}
				for _, ah := range heights {
					c := newForest(shape, assets, 10, ah)
					var circuit frontend.Circuit = c
					if name == "delegate2" || name == "delegate4" {
						d, err := NewDelegatePolicyCircuitWith(DelegateShape{Shape: transaction.Shape{NInputs: shape.Outputs, NOutputs: shape.Outputs}, OwnOnly: own})
						if err != nil {
							t.Fatal(err)
						}
						circuit = &forestDelegateCircuit{DelegatePolicyValues: d.DelegatePolicyValues, PolicyInputs: d.PolicyInputs, Forest: c.Forest}
					}
					count := compile(circuit)
					row := forestCount{Circuit: name, OwnOnly: own, Participants: shape.Outputs + shape.Withdrawals + 1, Assets: assets, ParticipantHeight: 10, AssetHeight: ah, Baseline: baseline, Constraints: count, Savings: 100 * (1 - float64(count)/float64(baseline))}
					rows = append(rows, row)
					fmt.Printf("FOREST %s own=%v participants=%d assets=%d heights=10/%d constraints=%d baseline=%d saving=%.4f%%\n", name, own, row.Participants, assets, ah, count, baseline, row.Savings)
				}
			}
		}
	}
	directory := os.Getenv("FOREST_RESULTS_DIR")
	if directory == "" {
		directory = t.TempDir()
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "forest-constraints")
	raw, err := json.MarshalIndent(rows, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path+".json", append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := os.Create(path + ".csv")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := csv.NewWriter(out)
	w.Write([]string{"circuit", "own_only", "participants", "assets", "participant_height", "asset_height", "baseline_v2_constraints", "forest_constraints", "savings_percent", "verification"})
	for _, r := range rows {
		w.Write([]string{r.Circuit, strconv.FormatBool(r.OwnOnly), strconv.Itoa(r.Participants), strconv.Itoa(r.Assets), strconv.Itoa(r.ParticipantHeight), strconv.Itoa(r.AssetHeight), strconv.Itoa(r.Baseline), strconv.Itoa(r.Constraints), fmt.Sprintf("%.6f", r.Savings), "full policy compile only"})
	}
	w.Flush()
	if err = w.Error(); err != nil {
		t.Fatal(err)
	}
}

func gadgetHeader(api frontend.API, pr, ar frontend.Variable, ph, ah int) frontend.Variable {
	return gadget.PoseidonHashWithState(api, []frontend.Variable{pr, ar, ph, ah}, 3)
}
