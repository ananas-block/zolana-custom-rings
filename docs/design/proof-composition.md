# Proof composition

The transfer circuits combine audit, policy, and withdrawal exemption constraints for the ring verifier.
SPP verifies its separate proof over the settlement. Review the agreement between those proofs through their shared transaction fields.
The exact statement encoding is in [Public inputs](../spec/crypto/public-inputs.md#transfer).

## Share constrained values

The [confidential circuit](../../prover/circuits/transfer/confidential.go) and
[anonymous circuit](../../prover/circuits/transfer/anonymous.go) pass audit output openings into policy checks.
Keep each output's owner, asset, amount, slot classification, and constrained hash together through that handoff.
Pairing one output's fields with another output's hash can screen a payment different from the settled payment.

Design section interfaces around constrained results. Construct each result where its opening constraints are added.
Let audit and policy consume the same result. Avoid interfaces that accept raw outputs and their openings as independently ordered slices.
The [policy view adapter](../../prover/circuits/policy/transaction.go) is the boundary to inspect for that pairing.

Preserve both output projections. The audit chain covers every output slot.
The private transaction chain uses each slot's hash multiplied by its UTXO indicator and skips zero entries.
Test dummy slots and exits when changing either projection.

Keep witness allocation outside the constraint flow. Read the constraint flow as envelope, output openings, sender binding, policy predicates, then statement binding.
Return constrained facts between sections. Keep statement assembly separate from witness construction.

## Derive gates from the rail

Derive the gate set once from statement-bound values and fixed family properties.
Use a small constructor or derivation function instead of allowing callers to choose unrelated gate combinations.
The [subject resolver](../../prover/circuits/policy/subjects.go) separates pool activation from individual lookup activation.
Review both levels whenever a predicate changes.

- Screening follows a nonzero policy hash. The table hash, rules, and recipient identities bind under screening.
- The own pool is active for screening, escrow, or exemption. The curator pool is active for screening with a foreign source.
- Sender queries require screening. Output owner queries require screening or escrow. Output asset and withdrawal subject queries require screening.
- Public asset queries require screening or exemption. Inactive slots add no subject obligation.
- Member outflow checks require screening and exclude the delegate rail. Delegate approval remains zero.
- In-proof and delegate rails open inputs under one sender. Delegate statements carry sender zero and require escrow.

A disabled predicate still leaves internal range checks, table decoding, and lookup constraints in the circuit.
Provide a valid inactive witness for each section. Test that an unrelated, well-formed inactive table does not change acceptance.
Do not describe a disabled section as unconstrained.

## Trace values across the program boundary

For each predicate, record its trusted source, statement field, enforcing constraint, and refusal test.
Distinguish values derived by the program from private values proven by the circuit.
Keep one source for each derivation and link to it from the review.

For an exempt withdrawal, follow the settlement legs through
[public slot folding](../../program-libs/interface/src/codec/spp.rs) into the asset, signed net, and gross fields.
Then follow the authenticated own-registry record into the
[threshold comparison](../../prover/circuits/policy/exemption.go).
The circuit consumes the gross total supplied in the statement. It does not reconstruct that total from its withdrawal witnesses.

A deposit and withdrawal of the same mint share a public slot. The deposit changes the net but does not reduce the gross withdrawal.
Test repeated mints, deposits before withdrawals, slot ordering, and totals beyond the exemption's range.
An oversized gross must fail exemption without imposing the exemption range on a non-exempt transfer.

Inspect the program binding for each rail. The instruction tag supplies delegate status, ring mode supplies escrow, and the owner rail supplies sender identity.
Keep delegate public-leg refusal in the program review. Circuit coverage does not establish that refusal.
Trace the exemption claim through account-prefix selection and co-signer demand.
Require ring proof verification before any SPP invocation can rely on that claim.

Read registry addresses and accepted revisions together. Policy and exemption checks in the combined statement use the same own root.
Test a root change between witness preparation and submission.

## Test the predicate and the binding separately

For a predicate test, construct an invalid transaction and recompute its statement before solving.
Otherwise, a failure can establish only that the public hash changed.
For a binding test, retain the proof and change a program-derived field or settled leg.

Cover each active and inactive gate with assignments that differ only in the obligation under test.
Include wrong input owners, missing records, wrong roots, foreign sources, invalid delegate flags, and threshold boundaries.
Mutate recipient identity, recipient body, disclosure, and private transaction hash independently.
Check entry and commitment input restrictions under their respective keys.

Use [Rust statement vectors](../../program-libs/interface/tests/statements.rs) as independent inputs to Go and TypeScript checks.
Compare ordered elements and counts before comparing hashes. A fixture that repeats the circuit's layout cannot establish agreement with another language.
Bind the statement schema and length explicitly when changing the encoding. A final nonzero version is not general length binding.

Use compiled BN254 constraints and proof verification alongside solve tests.
Check the verifier's public-input and commitment structure for each selected circuit.
The [gnark testing guide](https://docs.gnark.consensys.com/HowTo/debug_test) describes valid and invalid assignment checks across execution engines and backends.

## Choose capacities from supported transactions

Treat circuit capacity, SPP shape support, and serialized transaction fit as separate constraints.
Measure the assembled frame with its payer, co-signer, settlement accounts, and transaction header.
Cover SOL and SPL legs, account reuse, and both anonymous disclosure layouts.
An SDK size refusal does not establish a circuit or program restriction.

Choose withdrawal and input capacities per output family. A public gate does not remove the constraints of its inactive section.
Compare common transfers and wide withdrawals before removing a smaller capacity.
Measure proving latency, resident memory, and concurrent throughput on the serving hardware.
Key count and serialized key size do not establish those costs.

## Record the audit argument

Keep the cross-component argument in the guide and local invariants beside their constraints.
Name the assumption that each layer relies on and the test that challenges it.
Avoid property claims that cover more rails or gates than the enforcing code.
The [SNARK security taxonomy](https://arxiv.org/abs/2402.15293) provides a review model across circuit, proving system, and application boundaries.

## Predicate ledger

Each entry names the trusted source of a value, the statement field that carries it, the constraint
that enforces the predicate and the test that refuses its violation. Program sources are values the
program derives before verification. Private sources are witnesses the circuit proves. Constraints
live under `prover/circuits`, tests under `prover/circuits/transfer` unless named otherwise.

- Statement schema and length. Source, the program builds `TransferStatement::elements` in
  `program-libs/interface/src/proof/statement.rs`. Fields, `CRTX` first, the element count and the
  version last. Constraint, `closeStatement` in `transfer/transfer.go` and the one `HashChain4`
  equality that ends each `Define`. Tests, `TestTransferStatementsMatchRustVectors` compares the Rust
  vector element by element and `TestStatementBindsEveryElement` moves one element at a time against
  an unchanged witness.
- Screening. Source, the ring account's written policy hash, zero on an audit-only ring. Field,
  `policy_hash`. Constraint, `Rail.gates` in `policy/subjects.go` sets `screened`, then
  `Table.decodeWhen`, `assertRules` and `assertRecipients` bind under it. Tests,
  `TestConfidentialRefusals/sender on the frozen list` and `TestGateOffDropsItsPredicates/an unscreened ring
  ignores the table and the sender's lists`.
- Sender identity. Source, the sole owner signer under a policy on the signer rail, the framed owner
  key on the in-proof rail on every ring, zero on the signer rail off a policy and on the authority
  and anonymous rails. Field, `sender` on the confidential family.
  Private source, `SenderPkHash` on the authority rail and spent UTXO 0's owner or `SenderKey` on the
  anonymous rail. Constraint, `api.Select(c.Delegate, c.SenderPkHash, c.Sender)` in
  `transfer/confidential.go` and `anonymousSender` in `audit/anonymous.go`. Tests,
  `TestConfidentialRefusals/delegate with a statement sender`, `TestAnonymousRefusals/party identity
  equal to the hidden sender` and `TestConfidentialRailsSolve/in-proof on an audit-only ring`.
- Spent input ownership. Private source, the opened input slots. Constraint, `SpentBySender` under
  `in_proof OR delegate`, every slot a dummy on the signer rail, `spend` in `audit/anonymous.go` on the
  anonymous rail. Tests, `TestConfidentialRefusals/in-proof input of another owner`, `delegate move
  with a second member's input`, `delegate move without a spent input`, `signer rail opening an input`
  and `TestAnonymousRefusals/commitment key spending a default-ring note`.
- Settled outputs. Source, SPP's `private_tx_hash` from the frame, bound by SPP's own proof. Field,
  `private_tx_hash`. Constraint, `transfer.bindTransaction` over `shared.UtxoHashes` of the slots the audit
  opened, with the input chain of the rail. Tests, `TestExitEntersBothProjections` and
  `TestDummySlotEntersTheOutputChainOnly`.
- Output openings. Private source, every slot's wires. Fields, `output_chain`, `body_chain`,
  `recipient_key_chain` and `disclosure_chain`. Constraint, `shared.UtxoWires.Open` classifies and
  hashes once, `Deliver` and `Anonymous` in `audit` build every chain from that `shared.Output`, the
  policy screens the same values. Tests, the audit section refusals in
  `prover/circuits/audit/delivered_test.go` and `anonymous_test.go`.
- Recipients. Source, the frame's recipient identities under a policy on the confidential family,
  none on the anonymous family. Fields, `recipient_o`. Constraint, `assertRecipients` under
  `screened AND published`. Tests, `TestConfidentialRefusals/recipient other than the slot owner` and
  `TestAnonymousRefusals/recipient published on the anonymous rail`.
- Key escrow. Source, the ring mode, the frame flag must agree. Field, the `key_escrow` bit of
  `layout`. Constraint, `assertEscrow` in `policy/subjects.go` under `utxo AND key_escrow`, the owner
  record opened under `screened OR key_escrow`. Tests, `TestConfidentialRefusals/escrow of another key
  ciphertext` and `delegate without key escrow`.
- Outflow and approval. Source, the frame's approval flag, refused by the program on the authority
  rail. Field, `approval_required`. Constraint, `constrainOutflow` under `screened AND NOT delegate`,
  the approval equality in `Define`. Tests, `TestConfidentialRefusals/approval bit clear past the
  co-sign bound`, `approval bit set within every co-sign bound`, `delegate with the approval bit` and
  `TestGateOffDropsItsPredicates/the delegate rail bounds no outflow`.
- Withdrawal exemption. Source, the program folds the settled legs into `PublicSlots` in
  `program-libs/interface/src/codec/spp.rs`, the gross sum per asset excludes deposits. Fields,
  `exempt`, `asset_k`, `net_k`, `gross_k`. Constraint, `assertExemption` in `policy/exemption.go`
  against the asset record's `withdrawal_threshold` under `exempt`, the record opened under
  `screened OR exempt`. Tests, `TestConfidentialRefusals/exempt gross above the threshold`, `exempt
  withdrawal of an asset without a record`, `exempt gross past u64`,
  `TestGateOffDropsItsPredicates/an unexempt transfer ignores the gross` and
  `TestConfidentialRailsSolve/exempt withdrawal on an audit-only ring`.
- Registry roots. Source, the registry accounts at the frame's revisions, zero when no pool is
  active. Fields, `own_root` and `curator_root`. Constraint, `openRecordPool` under the pool gate and
  `pooledTable.lookup` holding every active query to an active pool. Tests,
  `TestConfidentialRefusals/screened under another own root` and the pool tests in
  `prover/circuits/policy/pooled_policy_test.go`.
- Authority rail. Source, the instruction tag. Field, `delegate`. Constraints, `AssertZeroWhen` on
  `in_proof`, on `sender` and on a clear escrow flag in `transfer/confidential.go`, the outflow gate
  above. Tests, `TestConfidentialRefusals/delegate with in_proof`, `delegate with a statement sender`,
  `delegate without key escrow`. The program refuses a public leg on this rail in
  `programs/custom-ring/src/instructions/transfer/accounts.rs`, no circuit covers that refusal.
- Exits and layout. Source, the exits bitmap of the frame and the key's family. Field, `layout`.
  Constraint, `DecodeLayout` pins every flag outside the key's free set and `Layout.AssertExits` holds
  the exits bit to the slots. Tests, `TestDeliveredAuditRefusals` and `TestAnonymousAuditRefusals`
  in `prover/circuits/audit`.

A disabled gate leaves the section's range checks, table decoding and lookups in the circuit. The
inactive witness is dummy slots, zero rows and index zero. The SDKs send it as the unopened pool,
the zero record at leaf zero under a canopy that admits it, `RecordPool::unopened` in
`program-libs/member-registry/src/record_pool.rs` and `unopenedRecordPool` in
`sdk-libs/ts/src/protocol/membership/member-opening.ts`.
