# Proof composition

A ring transfer settles only when the ring proof and SPP's proof both verify over values the ring program rebuilds. This guide states which side enforces each guarantee of statement version 3. Read it before you change a ring circuit, a statement builder or a program binding. The exact encoding is in [Public inputs](../spec/crypto/public-inputs.md#transfer).

## Enforcers

Each guarantee below names its enforcer as the subject of the sentence:

- The circuit states a local constraint in `prover/circuits`, true of every proof that verifies under the key.
- The program states a program fact. The ring or Storage program derives the value from accounts and the frame, or refuses the transaction before verification.
- SPP states a guarantee of the SPP program or its proof. The ring relies on it through shared values and does not check it again.
- A reader states an off-chain check. It protects the party that runs it and binds nobody else.

A statement element enforces nothing alone. It fixes a value, and a constraint or a program check gives the value its meaning.

## The cross-component argument

1. The program builds the statement from the frame it forwards to SPP. The statement hash is the one public input of the ring proof, so the prover picks no element the program derives.
2. The circuit opens each slot once through `shared.UtxoWires.Open`. Audit, policy and delivery read those wires, so no two sections describe different notes.
3. The circuit reopens `private_tx_hash` over the opened slots. SPP's proof binds the same hash to its nullifiers and outputs, so the opened slots are the slots SPP settles.
4. The program hands SPP the output hashes that `output_chain` covers. SPP zero-fills past `m`, and the circuit multiplies each cell past `m` by zero. Both sides read one list, the ring under `HashChain4` and SPP under `RightHashChain4`.
5. SPP derives every output blinding and `private_tx_blinding` from one seed. The circuit holds each published blinding to `TXOB` under `CRBS(tx_viewing_sk, salt)`. Slot 0 is always published, so the sealed key fixes SPP's seed.
6. The program reads each registry root live from the account the ring binds. A record opening under that root therefore carries the write rules of the Storage program and of ApplyRecords.

No Go test composes the ring proof with SPP's proof. Steps 3, 4 and 5 hold across the program binding.

## Predicate ledger

Tests sit under `prover/circuits/transfer` unless the entry names another path.

### The statement has one schema and one length

- The program builds `TransferStatement::elements` in `program-libs/interface/src/proof/statement.rs`.
- The circuit ends each `Define` with one `HashChain4` equality. `closeStatement` in `transfer/transfer.go` appends the element count and the nonzero version.
- `TestTransferStatementVector` pins the Go elements to the vector `go_vectors.rs` reads, and `TestTransferStatementsMatchRustVectors` compares the Rust elements. `TestStatementBindsEveryElement` moves one element against an unchanged witness.

### A rail is one fixed combination of bits

- The program sets `in_proof` from the frame's `OWNER_IN_PROOF` flag and `delegate` from tag 46. `TransactFlags::check` refuses the flag off the confidential rail and `EXEMPT` on the authority rail. `TransactCheck` refuses a public leg on the authority rail.
- The circuit holds the bits boolean, refuses `delegate` with `in_proof`, and holds `sender` to zero off the in-proof rail, in `assertRail`.
- The circuit requires the escrow flag on the authority rail, in `decodeLayout`.
- The tests are `TestRailCellsStayOnTheirRail`, and in `TestConfidentialRefusals` the cases `delegate with in_proof`, `delegate with a statement sender` and `delegate without key escrow`.

### Every input slot is an opened note or a canonical dummy

- The circuit opens each slot in `OpenInputs`, with no address input. A dummy holds `CheckDummy` fields.
- The circuit holds `input_count` to 1 through the class by `SelectCount`. A live note at or past the count is refused, and a dummy never precedes a live note.
- The program sets `input_count` to the frame's nullifier count.
- SPP's `AssertDummiesLast` orders its slots the same way, so entry `k` names nullifier `k`.
- The circuit feeds one list, `Utxo_i * Hash_i`, to `NonZeroHashChain` and to the evidence. A chain node cannot pose as an input, because each entry is an opened commitment.
- The tests are `TestInputSlotsHoldTheirDomain`, `TestDummyBetweenSpentInputsIsRefused`, `TestChainNodeCannotHideAnInput` and `in-proof UTXO at the input count`.

### Every live input answers its rail's owner predicate

- The circuit holds each live input to its rail's owner on the in-proof, authority and entry rails, in `AssertOwnedBy`. Input 0 is live there.
- The circuit holds each live input to the signer set on the signer rail. Slot 0 may be a dummy, so a public-funded transfer stays valid.
- The circuit reads `sender` as input 0's owner on the commitment key. Input 0 is live, `sender` is outside the set, and each other live input matches `sender` or a set member.
- The circuit holds each live input on a confidential or commitment key to this ring, in `AssertRingNotes`. `RingCircuit::transfer` keys no confidential spend of a default-ring note.
- SPP verifies each owner signer, and its hidden owner signature inside its proof. `HiddenOwnerSigners` requires a hidden input, so a frame of public owners belongs to the confidential family.
- `TestConfidentialRefusals` holds `signer input of an owner outside the set`, `signer input of another ring` and `in-proof input of another owner`.
- It also holds `delegate move with a second member's input` and `delegate move without a spent input`.
- `TestAnonymousRailSpends` holds the anonymous cases, and so does `TestAnonymousPublicCoOwners` in `prover/circuits/audit`.

### The signer set is the run SPP authorizes

- The program reads the SPP owner run, deduplicates by first occurrence, and builds `signer_count` and `signer_chain`. The payer enters only when the run lists it, and the program refuses a demanded co-signer in the run with `CoSignerIsOwner`.
- The program refuses an owner signer on the in-proof rail and a nonempty run on the entry key. It refuses an empty run under a policy on the signer rail.
- The program accepts the payer, the run and the co-signer as anonymous signers, and refuses any other signer with `InvalidAnonymousSigner`.
- The circuit holds each member past the count to zero, and chains zero at a count of zero, in `OpenSigners`. Both the in-proof and authority rails bind count zero.
- The tests are `TestSignerSetStatementBindsTheRun`, `TestSignerSetVector` and `TestSignerRailSpends`.

### Policy sections switch from the rail and `policy_hash`

- The circuit derives every gate once in `Rail.Gates`. A nonzero `policy_hash` sets `Screened`, and `Outflow` is `Screened` off the authority rail.
- The circuit activates the own pool under `Screened`, `KeyEscrow`, `Exempt` or `Delivery`, and the curator pool under `Screened` with a foreign source. `pooledTable.lookup` holds each active query to an active pool.
- The program writes `policy_hash` from the ring account, zero on an audit-only ring.
- A disabled section keeps its range checks, table decoding and lookups. The inactive witness is dummy slots, zero rows and index zero, sent as `RecordPool::unopened` and `unopenedRecordPool`.
- The tests are `TestGateOffDropsItsPredicates`, and in `prover/circuits/policy` `TestPooledPolicyModes` and `TestPooledPolicyConstraintMatrix`.

### Every spending owner is screened

- The circuit fixes `senders` per rail and never takes them as a witness. The signer rail reads the set. The in-proof and authority rails read their owner. The commitment key reads `sender` and the set. The entry key reads its one owner.
- The circuit screens each sender under every sender rule in `assertSenderRules`, whether or not it receives an output.
- The circuit holds the set to the key's sender rows under a policy. The confidential and commitment keys keep four rows, and the entry key keeps one. An audit-only ring takes the whole run.
- `TestSignerRailSpends` holds `a policy refuses more owners than its sender rows` and `a co-owner off the policy is refused though it receives nothing`.
- `sender on the frozen list` is a refusal, and `TestEveryCoOwnerIsScreened` sits in `prover/circuits/policy`.

### The settled outputs are the audited outputs

- The circuit opens each slot once in `OpenSlots`, then hands one `shared.Output` to delivery, the policy and the stream.
- The circuit reopens `private_tx_hash` in `bindTransaction`, over `Utxo_i * Hash_i` of the inputs and of the outputs.
- SPP binds `private_tx_hash` in its own proof. It holds each output's ring id to 0 or the ring's in `AssertRingMemberOrFree`, and to the ring's on the authority rail in `AssertRingMember`.
- The circuit holds a live note's `DataHash` and `RingDataHash` to zero. The auditor rebuilds its commitment with neither.
- The tests are `TestExitEntersBothProjections` and `TestDummySlotEntersTheOutputChainOnly`.

### Every published blinding derives from the sealed key

- The circuit holds each published slot to `TXOB` under `CRBS(tx_viewing_sk, salt)` in `AssertBlinding`, a hidden dummy included. Omission removes a suffix, so no index moves.
- SPP's `Transaction.Constrain` holds each output to `TXOB` under its private seed. The circuit publishes output slot 0 on every key, and SPP opens a nonzero published hash, so step 5 of the argument holds.
- The circuit proves no freshness of `tx_viewing_sk`. Its derivation from the wallet is SDK policy, and the authority rail draws it at random.
- The tests are `every output a dummy under an unrelated envelope key`, and in `prover/circuits/audit` `dummy blinding off the CRBS seed` and `TestDeliveredCompactCells`.

### Compact padding removes a suffix and nothing else

- The program parses `1 <= m <= N` and refuses a set exit or change bit at or past `m`. It refuses a frame of any other length.
- The circuit reads `SelectCount(m, 1, N)`. A live note at or past `m` is refused, and every statement cell past `m` multiplies by zero.
- The circuit runs each omitted slot's gadgets on the base point path, so the key's cost does not fall with `m`.
- A hidden dummy is a published slot. Its hash enters `output_chain` and stays out of the private chain.
- The tests are `TestConfidentialCompactSlots`, and in `prover/circuits/audit` `TestCompactPadding` and `TestDeliveredCompactCells`.

### A recipient identity is public only on the confidential family

- The program takes `recipient_o` from the frame under a policy, and the anonymous family has no such element.
- The circuit holds `recipient_o` to the slot owner under `Screened AND Published`, and to zero otherwise, in `assertRecipients`.
- The tests are `recipient other than the slot owner` and `recipient published on the anonymous rail`.

### An output owed an escrow opens the owner's record

- The program reads the `key_escrow` bit of `layout` from the frame and refuses a flag off the ring mode.
- The circuit holds each output owner's `escrow_key` to `Poseidon(nullifier_pk, ct_hash)` in `assertEscrow`. `shared.EscrowOwed` waives this for `ZeroNullifierPk` only, and such a note still answers every other rule.
- The escrow key names a ciphertext hash. Ring RPC checks the register key proof off chain, and no chain program verifies it.
- A direct write by the storage authority can escrow a key the auditor cannot open.
- The tests are `escrow of another key ciphertext`, `delegate output owner without a registered key` and `TestZeroNullifierKeyWaivesOnlyTheEscrow` in `prover/circuits/policy`.

### Each owner's debit stays within the asset's limits

- The circuit computes `debit_j_a` in `constrainOutflow` from opened inputs and ring outputs, per sender and asset, clamped at zero. Credits never move between owners.
- An exit reads `Ring = 0`, so it counts as leaving even when it pays its own owner.
- The circuit holds each debit to a nonzero `cap`, and sets the approval verdict above a nonzero `cosign_above`. `approval_required` equals that verdict.
- The program demands a co-signer on the approval bit, and refuses the bit on the authority rail.
- SPP's range checks bind input amounts through their hash, and `UintBytesBE` binds output amounts. Both bounds keep the comparisons inside `debitBits`.
- The tests are `TestDebitKeepsOwnersApart`, `TestSameOwnerExitCountsAsLeaving`, `TestDepositOffsetsASingleOwnersDebit` and `TestDebitVector` in `prover/circuits/policy`, and `approval bit clear past the co-sign bound`.

### Two owners never share a positive public net of a spent asset

- The circuit reads input owners and assets the program cannot see. It refuses a positive public net of an asset a mixed-owner transfer spends. `assertNoMixedDeposit` runs on every ring.
- An unrelated asset stays allowed, and so does a single owner.
- The SDKs refuse the same frame with `MixedOwnerDeposit` and `RING_MIXED_OWNER_DEPOSIT`, ahead of proving.
- The tests are `TestMixedOwnerDepositOfASpentAssetIsRefused` in `prover/circuits/policy`, `a mixed owner deposit of a spent asset`.

### A withdrawal exemption reads the settled gross

- The program folds settled legs into `PublicSlots` in `program-libs/interface/src/codec/spp.rs`. The gross per asset excludes deposits.
- The circuit holds each gross at or below the asset record's `withdrawal_threshold` under `exempt`, in `assertExemption`. It consumes the statement's gross and does not rebuild it from withdrawal witnesses.
- The program waives the withdrawals co-sign class on the frame's flag, with verification still ahead of any SPP call.
- The tests are `exempt gross above the threshold`, `exempt withdrawal of an asset without a record` and `exempt gross past u64`.
- `an unexempt transfer ignores the gross` holds the gate off.

### Roots come from the ring's registries

- The program reads each root live at the frame's revision, from the account the ring binds. `RootRead::transfer` returns at least `Own` on an anonymous ring.
- The program refuses an anonymous ring with no records at `Initialize`. It refuses a records registry of another ring at `Initialize` and at the records write, on every ring mode.
- A curator source reads list bits only, and delivery reads the own root only. `curatorColumns` in `policy/record_pool.go` projects nothing else.
- The tests are `screened under another own root`, `TestPooledPolicyBindsSubjectReferences` in `prover/circuits/policy`, and `programs/custom-ring/tests/rules/operator_rules.rs`.

### An address enters a record only through the owner

- The program stores the owner-signed address in an `AddressAuthorization` account. `owner.is_signer()` is the only authorization, so a wallet and a CPI signing PDA take one path.
- The program refuses a changed `nullifier_pk` at a later enrollment. It accepts a new `viewing_u` and moves `revision` by one.
- The program computes `address_hash` from the account on a write kind `ADDRESS`, then sets `applied_revision`. A second apply of one revision is refused, so an authority cannot roll an address back.
- The program builds a zero `address_hash` for every record and escrow write.
- The circuit keeps the old hash under a zero entry hash, in `RecordWrite.apply`. A relink of a predecessor keeps it too.
- `chain_start` binds the registry and batch revision. `queue_chain` binds the entry, so a root under any other address fails.
- The tests are `TestAuthorityBatchCannotSubstituteAnAddress` in `prover/circuits/registry`, and `programs/storage/tests/lifecycle.rs`.

### Address and escrow key name one nullifier key

- The circuit enforces this in the accepted state transition, `assertAddressMatchesEscrow`, so no account can be omitted and no alternate write path skips it.
- The check fires on a write that sets the address or fills an empty escrow key and leaves both present. An unrelated write opens no preimage.
- Each write reads the running state, so conflicting writes of one batch fail at the second.
- `EnrollAddress::check_record` in `sdk-libs/sdk/src/operations/storage.rs` and Ring RPC's `KeyAgreement::check` refuse a disagreeing key early. Neither is the enforcement.
- The tests are `TestAddressAndEscrowAgreeInEitherOrder`, `TestAddressAndEscrowMismatchIsRefused` and `TestPairingWriteWithoutPreimagesIsRefused` in `prover/circuits/registry`.

### Each live anonymous ring slot pays an enrolled address

- The circuit opens `address_hash(ring_id, owner, nullifier_pk, viewing key, revision)` against the owner's pool row, in `DeliverRecipients`. An absent record reads zero and never matches.
- The ring id in that hash keeps a record of another ring from opening.
- The circuit binds the sender's own row the same way, with the sender's nullifier key as a witness. A note under an older key can therefore spend into change at the bound address.
- The circuit derives each change bit from the exact address match, and the statement carries the result as `change_bitmap`. No witness flag decides it.
- The program refuses `change_bits` other than `0`, `0b1` or `0b11`, and refuses overlap with `exit_bits`.
- An exit opens no address, because `Ring` is zero on it. A dummy and an omitted slot open none.
- The tests are `TestSlotAddressBindsEveryKey`, `TestSenderAddressBindsTheBundleKey` and `TestChangeIsTheExactAddressMatch` in `prover/circuits/audit`, `a sender with no enrollment`.

### Live anonymous recipient bodies and sender bundles encrypt the opened fields

- The circuit holds a live ring recipient's body to scheme 11 under `CRING/rcp1` and its `CRDS` secret, in `assertRecipientBody`.
- The circuit binds `slot.Asset` to the body's mint chunks through `HashChain`, so a recipient learns a mint it has never seen.
- The circuit seals the bundle under `CRING/snd1` at index `m`, past every body's index. The bundle encrypts the same slot wires, recipient keys and `output_seed`.
- The program hashes each body and the bundle from the frame, into `recipient_body_chain` and `sender_bundle_digest`.
- A reader rebuilds the commitment with its own bound keys, so a match establishes ownership. The commitment is the only authentication, since the cipher has none.
- The tests are `TestRecipientBodyEncryptsTheOpening`, `TestSenderBundleBindsTheSlots` and `TestAnonymousBodiesVector` in `prover/circuits/audit`.

### Each anonymous tag has its form

- The circuit holds a live recipient's tag to `Poseidon(CRRT, CRDS_i)` and the bundle's to `Poseidon(CRST, CRDS_m)`, in `DeliverRecipients`. The live flag is computed, so a slot cannot take the dummy path.
- The circuit holds a hidden dummy's tag to `Poseidon(CRRT, s)` for a witness `s`, and proves no random sampling. Deliberate encoding through `s` stays open to a sender.
- The circuit holds a change, exit or omitted cell to zero. The program refuses a nonzero tag on change and a recipient, dummy or bundle tag at or above `q`.
- The program rebuilds `recipient_tag_chain` from the frame. SPP binds the same tag bytes through its external data hash, and does not prove what they are.
- No proof shows that a reader found its tag. [Discovery](../spec/crypto/disclosure.md#discovery) names the forms.
- The tests are `TestSlotTagIsDerived`, `TestSenderBundleTagIsDerived` and `TestRecipientTagChainBindsTheFrame` in `prover/circuits/audit`, and `program-libs/interface/tests/transact.rs`.

### The statement binds reply bytes only

- The program computes `reply_digest` from the frame's reply region, zero without the flag. It refuses the flag off the anonymous rail and a `reply_len` below 97.
- The circuit carries `reply_digest` as a public element and constrains no plaintext. The statement fixes presence, length and bytes.
- A reader stores a decrypted reply as a claim. `confirmReplyClaim` and the Rust `ReplyClaim` keep it unverified until the wallet confirms it.
- The tests are `the reply digest binds alone`, and `sdk-libs/ts/test/state/ring-anonymous-sync.test.ts`.

### A confidential body opens for its published key

- The circuit holds a ring output's body to the opening under `CRING/bdy1` and the `CRDS` slot secret, in `deliver`. Under key escrow the equality stops at 72 bytes.
- The circuit holds the slot's owner to the identity of the body's owner key.
- The circuit refuses a zero amount. A body names no asset, and balance ties it to a settled mint.
- The circuit constrains no plaintext on a hidden dummy's body. It binds only the bytes through `output_ciphertext_chain`.
- A reader compares the decrypted owner and nullifier keys with its own before it accepts the note, in `RingDeliveryOpening::open` and `openRingDelivery`. A rebuilt commitment alone does not establish ownership.
- The tests are `TestDeliveredAuditRefusals` in `prover/circuits/audit`.

### The auditor stream opens every slot and names every spent note

- The program supplies the auditor key from the ring account and hashes the transmitted envelope and records. It derives every length from family, layout, `N`, `m`, `n` and the exit bits.
- The circuit proves one key expansion and one `CTREncrypt` under `CRING/adt1` over every region, in `SealStream`. `countedDigest` covers the transmitted envelope, with its length as a tag.
- The circuit discloses `be32(hash_i)` per slot on the signer, in-proof, authority and commitment rails, and every opening on the entry key. A dummy reads zero.
- The circuit holds a live entry input to one nullifier key with no data hash and no ring data hash. The auditor can then test each hash under the note's tree id, with either ring id.
- The circuit proves no freshness of `eph_sk` or the salt. The Rust and TypeScript SDKs draw both per build, and `two_builds_of_one_transfer_draw_a_fresh_salt_and_a_fresh_ephemeral_key` pins Rust.
- The tests are `TestStreamRangesAreTheSharedVector`, `TestStreamRegionsHoldTheirPlaintext`, `TestAnonymousEvidenceHoldsEveryInputHash`, `TestAnonymousEntryEvidenceOpensEachInput` and `TestDeliveredSenderEvidenceFollowsTheInputCount` in `prover/circuits/audit`.

### Anonymous and exit records open their slot

- The circuit derives `exits_bitmap` from the opened slots, and pins each layout flag outside its free set in `DecodeLayout`. The bitmap is the one record of exits.
- The circuit opens a ring output's owner key, asset, amount and nullifier key on the anonymous family. It opens an exit's record on both families, and zeros on a dummy.
- SPP publishes each exit owner, and the scheme 3 exit body stays unproven by the ring.
- The tests are `TestAnonymousRecordsOpenTheirSlot`, `TestAnonymousRecordsKeepTheirKind`, `TestAnonymousRecordsStayOnTheirSlots`, `TestAnonymousAmountsStayBelowTwoTo64` and `TestLayoutRefusesTheClearBits` in `prover/circuits/audit`.

### A hidden sender stays apart from the public parties

- The program supplies the identities of payer, signing co-signer and withdrawal destination as `party_0` through `party_2`.
- The circuit refuses each nonzero party that equals `sender`, in `AssertAnonymousParties`.
- No layer checks a key only linked to the sender.
- The tests are `party identity equal to the hidden sender`, and `TestAnonymousParties` in `prover/circuits/audit`.

### A merge discloses its input list and keeps one owner

- The program sets `input_count` to the frame's nullifier count and checks the field count against the width. It reads `member_registry_root` on a key escrow ring only.
- The circuit keeps one owner, one asset and the ring across every slot, and sums the amounts into the output. It reopens `private_tx_hash` with slot `i` as SPP's slot `i`.
- The circuit holds `1 <= input_count <= width`, and every slot at or past the count to a dummy. A published slot can be a hidden dummy, so `input_count` never reads as a count of real inputs.
- The circuit discloses `be32(hash_i)` per slot, 32 zero bytes at a dummy, under the `CR_MD` pad keyed by a key sealed to the auditor.
- The circuit holds an escrowed owner's record to the nullifier key the merge spends under. `shared.EscrowOwed` waives this for `ZeroNullifierPk` alone.
- SPP's merge proof binds the same `private_tx_hash` and nullifiers, and range-checks every amount. SPP's own merge ciphertext stays unverified.
- The circuit refuses an owner equal to the payer or the co-signer on every ring mode, in `AssertAnonymousParties`, and holds `party_2` to zero. The program supplies the party identities.
- A merge proves no list membership. It moves no value between parties.
- The tests are `TestMergeRefusals`, `TestEscrowedMergeRefusals`, `TestMergePublishedCountHoldsHiddenDummies`, `TestMergeEscrowHoldsTheZeroKeyException` and `TestMergeParties` in `prover/circuits`.

### A deposit opens its notes to the auditor

- The program builds `context_hash` over the forwarded SPP data and supplies each root and `policy_hash` from its accounts.
- The circuit binds each occupied slot's commitment to its 96 byte opening, and that opening's key to `owner_pk_hash`. Blindings stay in the `CRDB` domain.
- The circuit screens the owner and asset rules through the section a transfer uses, runs no sender rule, and applies the escrow rule with the same `ZeroNullifierPk` waiver.
- The tests are `TestDepositRefusals`, `TestDepositScreensEachAssetOnItsRecord`, `TestDepositScreensEachAssetOnItsCuratorRecord` and `TestDepositEscrowHoldsTheZeroKeyException` in `prover/circuits`.

## Limits of the composition

- A proof constrains a dummy tag by its preimage alone, so a tag can carry information the sender chooses.
- A reader's coverage describes finalized history, and no proof backs it. [Reading through Ring RPC](audit-and-escrow.md#reading-through-ring-rpc) states what it claims.
- A hidden owner's privacy rests on the conditions in [privacy](privacy.md). No constraint covers them.

## Review practice

Keep each output's owner, asset, amount, class and hash together through a section handoff. Pairing one output's fields with another output's hash screens a payment other than the settled one.

For a predicate test, construct an invalid transaction and recompute its statement before solving. A failure otherwise proves only that the public hash changed. For a binding test, keep the proof and change a program-derived field or a settled leg.

Compare ordered elements and counts before hashes when you test across languages. A fixture that repeats the circuit's layout cannot prove agreement with another language. Use compiled BN254 constraints and proof verification alongside solve tests, and check the verifier's public input and commitment structure for each key.

Treat circuit capacity, SPP shape support and serialized transaction fit as separate limits. Measure the assembled frame with its payer, co-signer, settlement accounts and header. An SDK size refusal does not establish a circuit or program restriction.
