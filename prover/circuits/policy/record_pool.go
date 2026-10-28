package policy

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/lookup"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/registry"
	"github.com/helius-labs/zolana-custom-rings/prover/circuits/ringgadget"
)

type PoolSubject struct {
	Member      frontend.Variable
	RecordIndex frontend.Variable
}

type subjectPool struct {
	active frontend.Variable
	table  *lookup.Table
}

type recordQuery struct {
	active, member, index frontend.Variable
}

type pooledRecord struct {
	escrowKey  frontend.Variable
	onList     [NSources]frontend.Variable
	mintPolicy mintPolicyWires
}

type recordPool struct {
	active frontend.Variable
	table  *lookup.Table
}

func openRecordPool(api frontend.API, active, root frontend.Variable, records []registry.Record, proof registry.SharedQuadProof) (recordPool, error) {
	api.AssertIsBoolean(active)
	pool := recordPool{active: active, table: lookup.New(api, 6+NSources)}
	leaves := make([]frontend.Variable, len(records))
	for i, record := range records {
		leaves[i] = record.Hash(api)
		bits := api.ToBinary(record.Lists, registry.ListBits)
		policy := decodePooledMintPolicy(api, record.MintPolicy)
		row := []frontend.Variable{record.Member, record.Next, record.EscrowKey, policy.threshold, policy.cap, policy.cosignAbove}
		pool.table.Insert(append(row, bits[:NSources]...))
	}
	if err := proof.AssertLeavesWhen(api, active, root, leaves); err != nil {
		return recordPool{}, err
	}
	return pool, nil
}

func decodePooledMintPolicy(api frontend.API, packed frontend.Variable) mintPolicyWires {
	limbs, err := api.Compiler().NewHint(rangecheck.DecomposeHint, 3, 192, 64, packed)
	if err != nil {
		panic(err)
	}
	rc := rangecheck.New(api)
	for _, limb := range limbs {
		rc.Check(limb, 64)
	}
	base := new(big.Int).Lsh(big.NewInt(1), 64)
	api.AssertIsEqual(packed, api.Add(limbs[0], api.Mul(base, limbs[1]), api.Mul(new(big.Int).Mul(base, base), limbs[2])))
	return mintPolicyWires{threshold: limbs[2], cap: limbs[1], cosignAbove: limbs[0]}
}

func (p recordPool) resolve(api frontend.API, query recordQuery) pooledRecord {
	api.AssertIsBoolean(query.active)
	api.AssertIsEqual(api.Mul(query.active, api.Sub(1, p.active)), 0)
	row := p.table.Lookup(query.index)
	result := pooledRecord{escrowKey: row[2], mintPolicy: mintPolicyWires{threshold: row[3], cap: row[4], cosignAbove: row[5]}}
	copy(result.onList[:], row[6:])
	present := api.IsZero(api.Sub(row[0], query.member))
	ringgadget.AssertOrderedWhen(api, api.Mul(query.active, api.Sub(1, present)), row[0], query.member, row[1])
	live := api.Mul(query.active, present)
	return result.gated(api, live)
}

func (r pooledRecord) gated(api frontend.API, active frontend.Variable) pooledRecord {
	for i, bit := range r.onList {
		r.onList[i] = api.Mul(active, bit)
	}
	r.escrowKey = api.Mul(active, r.escrowKey)
	r.mintPolicy.threshold = api.Mul(active, r.mintPolicy.threshold)
	r.mintPolicy.cap = api.Mul(active, r.mintPolicy.cap)
	r.mintPolicy.cosignAbove = api.Mul(active, r.mintPolicy.cosignAbove)
	return r
}

func openSubjectPool(api frontend.API, records recordPool, subjects []PoolSubject) subjectPool {
	pool := subjectPool{active: records.active, table: lookup.New(api, 5+NSources)}
	for _, subject := range subjects {
		resolved := records.resolve(api, recordQuery{active: records.active, member: subject.Member, index: subject.RecordIndex})
		row := []frontend.Variable{subject.Member, resolved.escrowKey, resolved.mintPolicy.threshold, resolved.mintPolicy.cap, resolved.mintPolicy.cosignAbove}
		pool.table.Insert(append(row, resolved.onList[:]...))
	}
	return pool
}

func (p subjectPool) resolve(api frontend.API, query recordQuery) pooledRecord {
	api.AssertIsBoolean(query.active)
	api.AssertIsEqual(api.Mul(query.active, api.Sub(1, p.active)), 0)
	row := p.table.Lookup(query.index)
	api.AssertIsEqual(api.Mul(query.active, api.Sub(row[0], query.member)), 0)
	result := pooledRecord{escrowKey: row[1], mintPolicy: mintPolicyWires{threshold: row[2], cap: row[3], cosignAbove: row[4]}}
	copy(result.onList[:], row[5:])
	return result.gated(api, query.active)
}
