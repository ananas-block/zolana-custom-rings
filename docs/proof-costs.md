# Proof costs

Each proving key fixes a circuit family and its input and output width. A shape
such as 2x4 has two inputs and four outputs. The available ring keys are defined
by the [Go key catalog](../prover/ring/keys.go), mirrored by the
[Rust key catalog](../program-libs/interface/src/proof/key_catalog.rs), and pinned by
[proving-keys.lock](../prover/ring/proving-keys.lock). Use those files when
choosing a shape; a copied constraint count can become stale after a key
rotation.

## What each transaction proves

- A confidential transfer proves SPP's ring statement and one audit statement.
  A policy ring adds a member policy statement.
- An anonymous transfer proves SPP's anonymous statement and one anonymous
  audit statement. A policy ring adds a member policy statement.
- A delegate move proves SPP's ring authority statement, an audit statement
  and a delegate policy statement.
- An audited deposit proves a deposit statement; SPP's `ring_deposit` takes no
  separate proof.
- A merge proves SPP's ring merge statement. An anonymous ring adds a merge
  disclosure statement.
- Key registration and record application each prove their own statement.
- A withdrawal below configured thresholds can add a withdrawal exemption proof
  to waive withdrawal-scoped co-signing. Supplying the demanded co-signer needs
  no exemption proof.

## SPP statements

Input tree openings account for much of a transfer's work, so wider input
shapes cost more. The upstream [SPP fingerprint test](../zolana/prover/server/prover/fingerprint/fingerprint_test.go)
pins compiled constraints for representative shapes and rejects unplanned
changes.

## Audit statements

Packed audit keys cover smaller confidential and delegate outputs. Delivered
keys also prove that each output body opens for its recipient. Anonymous audit
keys additionally bind the hidden sender and its input class; an entry key
fully opens default-ring inputs. The [audit key tests](../prover/circuits/audit/keys_test.go)
pin the current compiled counts.

## Policy statements

A member policy proof opens the sender's record and records for each output's
owner and asset, and each nonzero public asset. Mint settings reuse these
authenticated asset records; proof work depends on the transaction shape rather
than the number of configured mints. A delegate policy proof also reopens spent notes. The
[policy key tests](../prover/circuits/policy/policy_test.go) enforce budgets for
the small output shapes; transaction size limits the wider shapes.

## Registry, deposits and merge disclosures

Record application, key registration, audited deposits and anonymous merge
disclosures have separate keys. The [registry tests](../prover/circuits/registry/registry_test.go)
pin opening constraints. Verify the current cost of any other key by compiling
it with the [ring key tests](../prover/ring/keys_test.go).

## Mint-record transition

Measured BN254 constraints before and after removing the three eight-mint tables:

| Circuit | Before | With mint records |
| --- | ---: | ---: |
| Member policy, 2 outputs, own registry, no public withdrawal metadata | 30,923 | 41,334 |
| Member policy, 2 outputs, curator | 49,039 | 59,776 |
| Member policy, 16 outputs, own registry | 167,536 | 183,813 |
| Apply 16 records | 232,892 | 240,828 |
| Deposit 8 | 148,936 | 149,392 |
| Withdrawal exemption, up to 3 distinct withdrawn mints | — | 12,102 |

The three public asset openings add a fixed cost to member policy proofs.
Leaf openings also hash two additional fields. Audit encryption circuits are
unchanged. Adding configured mints increases registry storage, not these circuit
sizes. The current counts are pinned in
[`constraints.json`](../prover/ringtest/ringkey/constraints.json).
