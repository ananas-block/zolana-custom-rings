The ring circuits prove that deposits, transfers, merges and registry updates satisfy the ring's applicable audit, policy and key escrow requirements.

Current implementation: PR #18, `alex/one-ring-proof` at `cfc83604` (4 November 2026), statement version 3 and key release v10. This describes the rebased code; [requirements.md](requirements.md) records the target design. Open design questions remain in the Notes subsections.

## Circuits

The ring circuits have **7 families and 27 instantiations**, each with its own proving key. Transfers use one combined ring proof for audit, policy, withdrawal exemption and recipient delivery, plus the separate SPP settlement proof. The signer, in-proof owner and delegate paths share the confidential family. Audit and policy reuse the same constrained output openings.

| Circuit family | Keys | Shapes |
|---|---:|---|
| Confidential transfer | 7 | Signer, in-proof owner and delegate; 2, 4, 8 or 16 outputs |
| Anonymous transfer | 5 | Ring inputs, with one hidden owner and optional public co-owners; 2, 4 or 8 outputs |
| Anonymous entry transfer | 3 | Full input openings for default-ring entry; 2, 4 or 8 outputs |
| Registry updates | 5 | 1, 2, 4, 8 or 16 record writes |
| Key escrow registration | 1 | One nullifier secret; proof checked by Ring RPC |
| Deposits | 4 | 1, 2, 4 or 8 deposited owner commitments |
| Merges | 2 | `8 -> 1` or `24 -> 1` |
| **Total** | **27** | |

### Transfer constraints

Inputs and withdrawals are fixed key capacities. A frame publishes `m` output slots up to the key's output capacity `N`, with omitted slots as a suffix. Where a row lists two withdrawal capacities, constraint counts follow the same order. Inactive sections and omitted slots still contribute compiled constraints.

| Family | Input capacity | Output capacity | Withdrawal slots | Constraints |
|---|---:|---:|---|---|
| Confidential | 24 | 2 | 4 / 32 | 358,832 / 562,193 |
| Confidential | 24 | 4 | 4 / 32 | 472,932 / 676,085 |
| Confidential | 16 | 8 | 4 / 32 | 661,511 / 865,703 |
| Confidential | 5 | 16 | 8 | 1,092,584 |
| Anonymous | 24 | 2 | 4 / 32 | 397,333 / 600,526 |
| Anonymous | 16 | 4 | 4 / 32 | 480,637 / 683,397 |
| Anonymous | 5 | 8 | 24 | 816,436 |
| Anonymous entry | 8 | 2 | 4 | 358,692 |
| Anonymous entry | 8 | 4 | 4 | 481,537 |
| Anonymous entry | 2 | 8 | 4 | 655,829 |

### Other circuit constraints

| Family | Capacity | Constraints |
|---|---|---|
| Registry updates | 1 / 2 / 4 / 8 / 16 writes | 17,161 / 33,371 / 65,757 / 130,370 / 259,596 |
| Key escrow registration | 1 key | 36,331 |
| Deposits | 1 / 2 / 4 / 8 outputs | 67,883 / 90,120 / 134,623 / 223,751 |
| Merges | 8 / 24 inputs | 59,535 / 84,577 |

Counts come from the [current constraint pins](../prover/ringtest/ringkey/constraints.json), with the catalog in [key_catalog.rs](../program-libs/interface/src/proof/key_catalog.rs) and release v10 in [proving-keys.lock](../prover/ring/proving-keys.lock). The [earlier proving-time benchmark](benchmarks/circuit-proving-times.json) measured the 90-key catalog at `cac79b02`; it does not provide timings for the current transfer circuits.

## Delivered audit

This is the audit section of the confidential transfer circuit.

1. **Auditor stream:** Encrypts the transaction viewing secret, the full hash of each published input and exit records to the auditor using X25519, a Poseidon KDF and AES-256-CTR.
2. **Recipient bodies:** Encrypt each ring output's blinding, amount, owner key and nullifier public key to its published viewing key; the auditor opens the same body using the transaction viewing secret.
3. **Disclosure:** Ring outputs need no second auditor copy of those fields. Exits have separate AES records. The output blinding seed is derived from the transaction viewing secret, salt and first nullifier.

```rust
// Logical layouts; Vec lengths and Option tags are not transmitted.
struct AuditEnvelopePlaintext {
    tx_viewing_secret: [u8; 32],
    input_evidence: Vec<u8>, // Encoding depends on the family; see below.
}

// Encrypted to the recipient; the auditor decrypts the same body.
struct DeliveredBodyPlaintext {
    blinding: Field,                  // 32 bytes, big-endian.
    amount: u64,                      // 8 bytes, big-endian.
    owner_key: [u8; 32],
    nullifier_pk: Option<Field>,      // Omitted under key escrow.
}

// Encrypted in the auditor stream; the exit owner is public.
struct ExitAuditRecordPlaintext {
    asset: Field,
    amount: u64,
    nullifier_pk: Option<Field>,      // Omitted under key escrow.
}
```

`Field` denotes a 32-byte field element. Delivered bodies are **104 B**, or **72 B** under key escrow; exit records are **72 B**, or **40 B** under key escrow. The recipient compares the decrypted owner and nullifier keys with its own before accepting the note. The body omits the asset, so the reader tries known assets against the commitment. Under key escrow, recovery of a nonzero-secret note's asset and commitment also needs the owner's escrow record; zero-secret notes can rebuild without one.

| Family | Encrypted input evidence |
|---|---|
| Confidential: signer, in-proof owner and delegate | Full 32-byte hash of each published input |
| Anonymous ring spend | Full 32-byte hash of each published input |
| Anonymous entry | Sender owner key and nullifier public key, then each published input's hash, amount, asset and blinding |

Evidence follows the published input count, including zero entries for published dummies, rather than the key's maximum capacity. Current frames use no hash prefixes. Each input hash identifies one commitment; an unknown input remains unresolved while transfer output records still decrypt independently.

Transfers, deposits and key registration share the labelled Poseidon KDF and AES schedule. Anonymous bodies, replies and sender bundles now use that schedule too, under separate labels. Merge keeps its older schedule and Poseidon field masking. Exit recipient bodies use Zolana's scheme 3 outside the ring encryption proof. See [Encryption](spec/crypto/envelope.md), [Disclosure](spec/crypto/disclosure.md) and [Proof composition](design/proof-composition.md).

## Anonymous audit

This is the audit and delivery section of the anonymous transfer and anonymous entry transfer circuits. New frames use scheme 11 recipient bodies and a scheme 12 sender bundle; the old scheme 1 and 2 readers remain only for historical transactions.

```text
Anonymous transaction
|
+ Public context
|  + Transaction viewing public key
|  + Salt
|  + Published output count and exit/change bits
|  + Public co-owner signers, when present
|
+ Output slots
|  + Output commitment
|  + Proven discovery tag
|  + Recipient ciphertext - AES, checked by the ring proof
|  |  + Blinding, amount, mint
|  + Optional reply ciphertext - bytes committed, contents unchecked
|     + Claimed sender viewing key, owner key, nullifier public key, data
|
+ Sender message
|  + Proven sender bundle tag
|  + Sender ciphertext - AES, checked by the ring proof
|     + First change mint and amount
|     + Second change amount, native SOL
|     + Output blinding seed
|     + Recipient viewing keys, one cell per published output
|
+ Auditor message - encryption checked by the ring proof
   + Auditor view tag
   + Ephemeral public key
   + One AES-256-CTR stream
      + Envelope: transaction viewing secret and spent-input evidence
      |  + Ring spend: full input hashes
      |  + Entry: sender keys and each input's hash, amount, asset, blinding
      + Record per ring output: owner key, asset, amount, nullifier public key
      + Record per exit: asset, amount, nullifier public key
```

The auditor derives output blindings from the transaction viewing secret, salt and first nullifier. Each published ring slot, including change or a dummy, has a **104 B** auditor record; a dummy encrypts zero plaintext. Exit records have **72 B**. The anonymous families disable key escrow.

The proof checks each live ring output's owner, nullifier public key and viewing key against its owner-authorized address in the ring's own records. The sender's bundle key is checked against the sender's enrolled address, including on entry and when there is no change.

```rust
struct AnonymousRecipientPlaintext {
    blinding: Field,
    amount: u64,
    mint: [u8; 32],
}

struct AnonymousSenderBundlePlaintext {
    first_change_mint: [u8; 32],
    first_change_amount: u64,
    second_change_amount: u64,       // Native SOL.
    output_blinding_seed: Field,
    recipient_viewing_keys: Vec<[u8; 32]>, // One cell per published slot.
}

// Optional sender claim; its contents are not checked by the proof.
struct ReplyMetadataPlaintext {
    viewing_u: [u8; 32],
    owner_key: [u8; 32],
    nullifier_pk: Field,
    data: Data,
}
```

A recipient body has **72 B**. A change slot has no body and is reconstructed from the sender bundle; change requires the same owner, nullifier public key and viewing key as the sender's enrolled address. A dummy has random recipient bytes. Recipient and bundle tags derive from slot secrets; dummy tags prove a Poseidon preimage, not random sampling.

The sender bundle has **80 + 32 × m B**, where `m` is the published output count. Viewing-key cells are zero for change, exits and dummies. Optional replies have a frame-wide padded length of at least **97 B** per body-bearing slot; a slot without a claim uses random bytes. Replies remain untrusted until the wallet confirms them. Exit recipient bodies keep Zolana's confidential encoding and their encryption remains unchecked by the ring proof.

### Anonymous encryption sizes

Sizes assume one published ring input, one change output, no exits and no optional reply. They count the encryption portion of the compact ring frame, excluding output commitments, proofs, input nullifiers, policy data, frame headers and bitmaps, and Solana transaction overhead.

| Published outputs | Recipient/dummy slots | Recipient ciphertexts | Sender bundle | Auditor ciphertexts | Keys, tags and salt | Total encryption data |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 1 | 72 B | 144 B | 272 B | 176 B | **664 B** |
| 4 | 3 | 216 B | 208 B | 480 B | 240 B | **1,144 B** |
| 8 | 7 | 504 B | 336 B | 896 B | 368 B | **2,104 B** |

Recipient ciphertexts are **72 × (m - 1) B**. Auditor ciphertexts are **32 B** for the transaction secret, **32 B per published input** and **104 B per ring slot**. Keys, tags and salt total **112 + 32 × m B**: transaction viewing key, salt, one tag per output, sender bundle tag and auditor ephemeral key. Fixed body lengths are not transmitted. Stream padding is not transmitted either.

Each additional commitment input adds **32 B**. Entry evidence instead adds a **64 B** sender/key head and **104 B per input**. Enabling replies adds the padded reply length per recipient/dummy body and one 2-byte length field. These totals do not establish that a complete transaction fits.

### Notes

1. Optional reply metadata now supplies the claimed sender's full return address and data. Without a reply, the recipient learns no sender address from its body. The claim is unauthenticated and requires wallet confirmation.
2. The implementation retains full input commitments on every rail. The review proposal is to identify spends from derived nullifiers instead, given complete audited history and access to the required nullifier secrets; default-ring inputs still need their openings supplied.
3. Mixed-owner support is partly implemented: anonymous ring spends support one hidden sender and public co-owners, with at most four screened owners on policy rings. Entry remains single-owner and single-nullifier-key, and the SDK rejects mixed ring/default entry inputs. In-proof and delegate transfers also require one input owner.
4. The earlier prototype traded a separate Poseidon disclosure for verified sender and recipient AES fields, using a Poseidon KDF and Zolana's optimized X25519 while dropping input linkability. The measurements below use the old `cac79b02` audit circuit, exclude the new combined policy and exemption sections, and are **historical**, not current transfer costs. The 16-output row is an experimental extension; current anonymous keys stop at 8 outputs.

   | Outputs | Old baseline bytes | Prototype bytes | Saved bytes | Old audit constraints | Prototype constraints | Added constraints |
   | -------: | ------------------: | ---------------: | -----------: | ---------------------: | ---------------------: | -----------------: |
   | 2       | 760                | 632             | 128         | 57,604                | 119,715               | 62,111            |
   | 4       | 1,398              | 1,110           | 288         | 64,202                | 191,972               | 127,770           |
   | 8       | 2,642              | 2,066           | 576         | 77,733                | 336,725               | 258,992           |
   | 16      | 5,162              | 3,978           | 1,184       | 104,749               | 626,978               | 522,229           |


    [Historical measurements and assumptions](benchmarks/anonymous-audit-poseidon-kdf-tradeoff.json). Mandatory nullifier-key escrow would let the auditor compute spends directly, but output identities and values would still need verified recovery.
5. New recipient bodies, sender bundles and discovery tags are now checked by the proof. The old scheme 1/2 groups are named `committed` and `uncommitted` in the historical reader, rather than claiming their encryption was verified.
6. The ring delivery schemes now share the Poseidon KDF and AES schedule, while merge and exit recipient encryption remain exceptions. The target requirements only demand verifiable encryption to the auditor; proving recipient delivery and requiring address enrollment are additional implementation requirements.
7. Compact output padding and hidden dummies are supported: a frame publishes `m <= N` slots and omits a suffix. Key capacities, four-owner policy screening, single-owner entry and dataless outputs still restrict SPP flexibility. Confidential policy frames publish zero recipient identities for dummies, so dummy privacy is not uniform across modes.
8. Ring RPC now checks indexed events against finalized canonical transactions and reports `through_slot` and coverage with its unspent-note view. Full input hashes identify spent notes without holding their nullifier secrets; deriving nullifiers or recovering a merged wallet opening still needs the corresponding key.
9. `shared.EscrowOwed` waives escrow when the nullifier public key is `Poseidon(0)`, on transfers, deposits and merges. This waives escrow only; anonymous recipients and senders still need owner-authorized address enrollment, including a PDA's controlling program signing through CPI.
10. Confidential and anonymous transfers still use separate circuit families. We should consider one family with the program supplying a zeroed unused hash-chain section.

## Merge

The ring merge circuit opens inputs under one owner, one asset and one nullifier secret, checks the summed output and SPP private transaction hash, and encrypts **only the ordered input hashes** to the auditor. A dummy contributes a zero hash. It supports fixed widths **8** and **24**, with **9** or **25** masked field elements.

Merge seals a disclosure key using its older AES schedule and masks the packed input list with Poseidon field pads. The output's owner, asset and amount are inherited from known inputs rather than encrypted directly. Missing input metadata leaves the merge and dependent merges unresolved. A wallet opening also requires deriving the output blinding from the nullifier secret and first nullifier.

Under key escrow, merge checks the owner's record and escrow key unless the nullifier public key is `Poseidon(0)`. It does not run the transfer rule table. See [Merge disclosure](spec/crypto/disclosure.md#merge-disclosure).

**Notes:**

1. The review proposal is to remove the per-input merge disclosure so that input capacity is not constrained by ciphertext growth, and verifiably encrypt only the new output. Spend tracing would use derived nullifiers with complete audited history and the necessary secrets. This is not implemented.
2. Merge currently performs no general transfer-policy checks because owner and asset remain unchanged, matching the target requirements; conditional escrow checks remain.
3. Merge remains an exception to the shared encryption schedule.

## Policy

The policy rules are a `RuleTable`; a `SourceMap` selects the registry supplying each list. They are checked inside the transfer proof. Screening is active when `policy_hash` is nonzero; escrow, withdrawal exemption and anonymous address delivery activate their own checks independently.

```rust
struct RuleTable {
    rules: [Rule; 16],
    len: u8, // Number of active rules.
}

struct Rule {
    subject: Subject,
    source: RuleSource,
    guard: Guard,
}

enum Subject {
    OutputOwner = 1,
    Sender = 2,
    ExitDestination = 3, // Rejected by current policy validation.
    Asset = 4,
}

enum RuleSource {
    // OR across the listed presence and absence alternatives.
    Lists { present: ListSet, absent: ListSet },
}

struct ListSet(u8); // Bit i selects list i + 1.

enum Guard {
    Always,
    AboveAmount(u64),
    AboveAmountByAsset, // Threshold comes from the asset's MemberRecord.
}

struct SourceMap {
    slots: [PolicySource; 8],
}

// Source for one list; membership values live in MemberRecord.
struct PolicySource {
    list_id: u8,         // Zero for an empty slot; otherwise 1 through 8.
    registry: [u8; 32],   // Registry field; zero selects the ring's own registry.
}
```

`policy_hash` commits to the domain, encoding version (currently 12), eight source slots, rule count and sixteen encoded rule rows. These are zero-padded to 44 field elements and folded with Poseidon. Unused encoded rule rows are zero. Per-asset thresholds and limits remain in `MemberRecord`.

Current limits are **16 rules**, **8 positional source slots** and **2 registry trees**: the ring's own tree and at most one curator tree. Each list selects one source tree. Sender rules screen each spending owner represented by the rail, up to four on confidential and anonymous commitment keys and one on entry keys. Owner and asset rules screen outputs and public withdrawal recipients/assets. Asset rules do not directly iterate input assets. A standalone deposit runs asset rules only, not recipient owner rules.

Outflow caps and approval thresholds aggregate each owner's spent amount per asset, less returns to the same owner in ring outputs, with a floor of zero. Exits count as leaving even when paid to the same owner. A mixed-owner spend cannot also publicly deposit an asset it spends. Fixed-threshold recipient guards require a single asset; per-asset recipient guards use the asset record's threshold.

Delegate transfers still run list rules and amount guards, but skip outflow caps and amount-triggered approval. The program rejects public deposit/withdrawal legs and SPP rejects default-ring outputs on this path. This differs from the target delegate policy, which bypasses ordinary policies and permits withdrawals and exits.

Withdrawal exemption remains a separate flag: the proof checks gross public withdrawals per asset against the own record's threshold, and the program waives only withdrawal-class co-signing. Other demanded approval classes remain. Mint settings, withdrawal thresholds, escrow keys and enrolled addresses come from the own tree.

### Lists

1. **Allow:** Authority-controlled approval of owners or assets for policies requiring allowlisting.
2. **Block:** Authority-controlled list of owners or assets that policy rules can exclude.
3. **Frozen:** Separate authority-controlled list used to stop selected owners from sending.
4. **Approval:** Additional authority-controlled approval list usable in policy rules and enrolment.

Allow, Block, Frozen and Approval are the policy-readable lists and affect transfers only when rules reference them. Record writes publish their member identifiers and list flags; the current registry does not implement private list entries.

### Non Policy Lists

1. **RingViewing:** Wallet-controlled preference flag with no current viewing behavior.
2. **Recovery:** Reserved, unused list ID; accepts no writes and cannot be read by policy rules.
3. **Reader:** Grants access to decrypted activity through Ring RPC; authority-controlled grants cover the ring, and wallet grants cover one wallet. Reader is excluded from transaction policy rules.
4. **Escrow:** Reserved list ID for nullifier-secret escrow; registration is recorded through `escrow_key` and is not a rule-readable list.

**Notes:**

1. Registry zero still selects the ring's own registry. We should consider identifying it like other approved source trees instead of using a special sentinel.
2. **RingViewing:** Who may view, for how long or how many requests, and how should this differ from Reader? The flag currently implements none of those permissions.
3. **Recovery:** The earlier question is resolved by reserving the list ID and rejecting writes; no recovery behavior is implemented.
4. **Reader:** The earlier policy-reference concern is addressed: Reader is excluded from `POLICY_LISTS`. Ring-wide and wallet-specific grants remain separate from moving funds; a tree-backed wallet grant uses `Poseidon(CRWG, wallet, reader)` as its member key.
5. **Proposed tree permissions:** Policy config should specify which trees may serve each purpose. Inclusion checks, such as KYC allowlisting, may accept any of several explicitly approved trees. An absence-based check must use exactly one configured authoritative tree; the prover must not choose a tree missing a record that exists in another source. The same requirement applies when absence supplies default mint settings or limits. This is not implemented by the current single-curator source map.

## Member policy

The membership-tree leaf is a `MemberRecord`:

```rust
struct MemberRecord {
    member: [u8; 32],     // Owner, asset, reader or wallet-reader grant identity.
    next: [u8; 32],       // Next member in sorted order.
    lists: u64,          // Bits: 0=Allow, 1=Block, 2=Frozen, 3=RingViewing, 4=Recovery (reserved), 5=Reader, 6=Approval, 7=Escrow (reserved).
    escrow_key: [u8; 32], // EscrowKey hash, or zero before registration.
    mint_policy: MintPolicy,
    address_hash: [u8; 32], // AuthorizedAddress hash, or zero before enrollment.
}

// Hash includes CRAD, ring_id, member, nullifier_pk, packed viewing_u and revision.
struct AuthorizedAddress {
    ring_id: Field,
    nullifier_pk: Field,
    viewing_u: [u8; 32],
    address_revision: u64,
}

// Hashed as Poseidon(nullifier_pk, hash_bytes(ciphertext)).
struct EscrowKey {
    nullifier_pk: [u8; 32],
    ciphertext: [u8; 32], // Encrypted NullifierKeyPlaintext.
}

// Encrypted to the auditor using X25519, a Poseidon KDF and AES-256-CTR.
struct NullifierKeyPlaintext {
    padding: u8,               // Always zero.
    nullifier_secret: [u8; 31],
}

struct MintPolicy {
    threshold: u64,
    cap: u64,
    cosign_above: u64,
    withdrawal_threshold: u64,
    limits: AssetLimits,
}

struct AssetLimits {
    sender_cap: u64,
    sender_window_slots: u64,
    volume_cap: u64,
    volume_window_slots: u64,
    deposit_cap: u64,
    deposit_window_slots: u64,
    withdrawal_cap: u64,
    withdrawal_window_slots: u64,
}
```

The record is packed into **ten field elements** and hashed with Poseidon, with `address_hash` as the last field. For a wallet, `member` is the hash of its tagged owner public key. A present subject opens its record; an absent subject opens the predecessor whose `member < subject < next`, returning zero list bits and settings.

The address hash includes the ring ID and owner identity, nullifier public key, viewing key and revision. The owner authorizes it, including through signed CPI for a PDA, before it is applied to the tree. Nullifier keys stay fixed on a registry while viewing keys can rotate. An address and an escrow key in the same record must name the same nullifier public key. The own registry is scoped to one ring; curator registries can still serve shared lists.

The combined transfer circuit still has separate own and curator record pools. Both use shared Merkle paths, and repeated subjects can reuse authenticated records. With `S` sender rows, `O` output slots and `W` withdrawal slots, capacity is `S + 2*O + W + 3` per tree for the current keys. `S` is four on confidential and anonymous commitment keys, one on entry keys. The 16-output confidential key has 8 withdrawal slots and therefore **47 own + 47 curator record slots**; these are capacities, not a minimum count of distinct members. Conditional checks do not remove the compiled capacity.

Curator lookups project only list columns from the authenticated full leaf; they do not require the leaf's escrow, address or mint settings to be zero. Own-tree lookups also provide those fields. Pool capacity is fixed by the transfer key constructor.

**Notes:**

1. `escrow_key` remains a sibling of `mint_policy`. Curator projection now avoids requiring own-tree fields to be zero in a curator leaf. Should escrow be nested with the own-tree settings, or shared through a registry so users need not register it for each ring? RegisterKey proofs can be reused for the same member and auditor across rings, but each ring keeps its own record; enrolled addresses remain ring-scoped.
2. One record pool with an authenticated tree selector can replace the separate own and curator pools. At the same total record capacity, this saves essentially no constraints. Savings come from reducing the fixed record budget; smaller separate pools already achieve similar counts. A unified pool allows that budget to be allocated flexibly between trees.

   The following **historical prototype** predates proof consolidation (source `ec767e79`). Its separate 16-output member-policy baselines cost 263,885 constraints with no withdrawal slots and 501,564 with 32 withdrawal slots; these are not current combined transfer costs:

   | Withdrawal slots | Old record slots | Unified record slots | Prototype constraints | Saved vs. old baseline |
   | ----------------: | ----------------: | --------------------: | ---------------------: | ----------------------: |
   | 0                | 69               | 69                   | 263,997               | -112                   |
   | 0                | 69               | 36                   | 174,650               | 89,235                 |
   | 0                | 69               | 16                   | 115,741               | 148,144                |
   | 0                | 69               | 6                    | 84,696                | 179,189                |
   | 32               | 136              | 136                  | 502,307               | -743                   |
   | 32               | 136              | 68                   | 321,315               | 180,249                |
   | 32               | 136              | 36                   | 234,690               | 266,874                |
   | 32               | 136              | 6                    | 144,736               | 356,828                |


    Smaller budgets limit distinct authenticated (tree, record) pairs; they do not preserve the current worst-case record diversity. Repeated owners and assets can reuse records. The prototype keeps both registry roots, shared upper Merkle paths per tree, policy-source checks, and own-tree restrictions for escrow and mint settings. Subject-pool capacities remain unchanged. For comparison, separate pools with 18 records each cost 174,591 constraints versus 174,650 for a unified 36-record pool. These are compiled prototype counts; applying the design to the combined transfer circuits requires new measurements, keys and witness changes. Honest witnesses, non-membership and tree-selection rejection checks passed. [Raw measurements](benchmarks/unified-record-pool-tradeoff.json) and [reproducible experiment](benchmarks/unified-record-pool-experiment.tar.gz).



&nbsp;

### Notes:

1. even if users disclosed their nullifier secret the
