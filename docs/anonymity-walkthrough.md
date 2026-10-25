# Anonymity Walkthrough

A custom ring is a Solana program that governs its notes in the zolana shielded pool (SPP). SPP moves a ring note only when the ring program signs, and the ring program signs only after it verifies the ring's proofs. Every transfer carries an audit proof that the ring's auditor key opens it. An anonymous ring also hides the sender and the recipient of each transfer from chain observers. The auditor still opens every transfer. [Spec](spec.md)

## Terms

### Mode

A **mode** fixes the rail of every transfer on a ring. `CreateConfig` sets `Anonymous` for the `Anonymous` and `AnonymousPolicy` ring kinds and `Confidential` for the `AuditOnly` and `Policy` kinds (`programs/custom-ring/src/instructions/configuration/setup/create_config.rs:65`).
- `Confidential`: owners sign in public, and each ring output publishes its recipient's viewing key.
- `ConfidentialEscrow`: `Confidential` with key escrow and a delegate. Each output owner's nullifier secret is sealed to the auditor, and the delegate can move escrowed notes.
- `Anonymous`: the sender and the recipient are hidden from chain observers.

### Rail

A **rail** is the signing form of a transfer. The instruction tag and the mode select it, never the frame, the transfer's compact instruction data (`RingRail::of`). The payer is SPP account `0` and pays rent and fees. A co-signer is an optional key in the ring config. The program demands its signature when its scope or an outflow limit names the operation.

| Rail | Mode | Who signs | SPP circuit |
| --- | --- | --- | --- |
| Confidential | `Confidential`, `ConfidentialEscrow` | Each owner signer, the payer and a demanded co-signer | `ConfidentialRingEddsa` |
| Anonymous | `Anonymous` | The SPP payer and a demanded co-signer. The hidden owner signs inside the SPP proof. | `AnonymousRingEddsa` |

A third rail, the delegate rail, runs `DelegateTransact` in `ConfidentialEscrow` mode only.

### Hidden owner

The **hidden owner** is the sender on the anonymous rail. Its Ed25519 signature verifies inside SPP's proof, so its key never reaches the chain. Every spent note belongs to it.

### Ring address

A **ring address** is the recipient's shielded address with a per-address viewing key `u`, the ring and the pairing rows. `u` is an X25519 public key, and only the recipient holds its secret. The wallet derives `u` from its viewing key, the ring and an address index. A pairing row `(mint, min_amount)` admits a first contact (below) of that mint at or above that amount, and the zero mint admits every asset. The address also carries the recipient's signing key, whose identity owns the recipient's notes. It is shared off chain and never published.

### Payment tag

A **payment tag** is 16 bytes. SPP publishes a 32-byte owner tag for each output. On a confidential ring it is the recipient's `u`. On an anonymous ring it is `0^16 || tag`, 16 zero bytes and then the payment tag. A recipient finds its notes by these tags.

### Inbox stream

The **inbox stream** is the tags every holder of the address derives:
```
inbox_key = Poseidon(CRIK, ring_id, pack_be(0x04 || u))
tag       = low128(Poseidon(CRIT, inbox_key, epoch, j)),  j < 64
```

`CRIK`, `CRIT`, `CRPK`, `CRPT` and `CRAT` are domain tags. `ring_id` is `hash_bytes` of the ring program id. `pack_be` splits bytes into field elements, `low128` takes the low 16 bytes, and `j` is the tag index. The recipient scans 64 tags per stream and epoch. [Hashing](spec/crypto/hashing.md#anonymous-streams)

### First contact

A **first contact** is a sender's inbox payment to an address whose pairing admits it. The sender draws a transaction viewing key per transfer and seals its secret `tx_viewing_sk` to the auditor. The slot secret `s1` of the payment hashes `X25519(tx_viewing_sk, u)` with the transaction's public key, `u`, the salt, the output index and the first nullifier. The sender knows `tx_viewing_sk`, the recipient computes the same X25519 value from the secret of `u`, and the auditor opens `tx_viewing_sk`. All three therefore know `s1`.

### Pair stream

The **pair stream** is the tags of one sender and one address after a first contact:
```
pair_key = Poseidon(CRPK, s1)
tag      = low128(Poseidon(CRPT, pair_key, epoch, j)),  j < 64
```

Only the sender, the recipient and the auditor derive it, so other holders of the address cannot find later payments. It is valid from the first contact's epoch for `K_PAIR_EPOCHS` (32) epochs. The wallets also retire a pair 8 epochs after its last payment.

### Epoch

An **epoch** is `slot / 2^18`. The program binds the landing epoch, or the previous one when the frame sets `PREVIOUS_EPOCH`. That flag lets a transfer proven late in one epoch land in the next.

### Party identities

The **party identities** are `solana_owner_identity` of three public keys, `0` when absent: the payer, the configured co-signer, and the one withdrawal destination key. `solana_owner_identity(key)` is `hash_bytes(0x53 || key)`, the owner identity zolana stores in a note. The Solana fee payer of the outer transaction is no party identity, and the program does not check it.

### Entry spend

An **entry spend** spends default-ring notes, the SPP notes outside every ring. It publishes the hidden owner's identity as `default_owner_tag`, so it names its sender. It cannot also spend ring notes.

### Decoys

**Decoys** are 7 leaves of the tree that holds the first contact. A pair payment reads their Merkle proofs in one indexer request with the first contact's, in an order keyed by `s1`. The indexer therefore cannot tell which leaf is the first contact.

## Logic

**The sender stays hidden.** The program refuses every SPP signer but the payer. The hidden owner signs inside SPP's proof. The audit proof shows the hidden owner differs from each party identity.

**The recipient stays hidden.** Each tag derives from the recipient's address and the epoch. Each body is `AES-256-CTR(blinding || amount)` under a key derived from the slot secret, and the audit proof proves it for that `u`. Only the holder of the secret of `u` and the auditor open it. The auditor still opens every output.

**A first contact turns into a pair stream.** The ring data hash is a field SPP commits in each output note. The first contact's ring data hash is `Poseidon(CRAT, s1, 0^16 || tag)`. A later payment sets the `ANCHOR` frame flag and publishes the first contact's tree and root index. The program reads that root from the SPP tree as `first_contact_root`. The audit proof opens the first contact under it, as an inbox payment to the same address and owner, fewer than 32 epochs before.

### Example: Alice pays Bob twice

Bob issues ring address `#3`, address index 3, with the default pairing, any asset at any amount, and gives it to Alice only. Alice pays from Alice's ring notes. A relayer, a third party that submits and pays for the transaction, is the payer.

```
Payment 1, epoch E:      Inbox  tag = low128(Poseidon(CRIT, inbox_key_3, E, j1))
Payment 2, epoch E + 5:  Pair   tag = low128(Poseidon(CRPT, pair_key, E + 5, j2))
                         ANCHOR, tree and root index of payment 1
```

<aside>

**Requirement:** the relayer and the Solana fee payer do not link to Alice **AND** address `#3` goes to Alice only.

</aside>

| Observer | Payment 1 (inbox) | Payment 2 (pair) |
| --- | --- | --- |
| Chain observer | The relayer, the epoch, a 16-byte tag, the body and the output hash. Not Alice, not Bob. | The same, plus `ANCHOR`, the tree and the root index. It learns a pair stream is in use and bounds the first contact in time. |
| Any holder of address `#3` | Derives the 64 inbox tags of epoch `E`, sees that `#3` was paid, and reads Bob's signing key from the address. | Nothing. The pair tags need `s1`. |
| Bob | Finds the tag, opens the body with the secret of `u` and records the pair key. Learns no sender key. | Finds the pair tag and links payment 2 to the sender of payment 1. |
| Auditor or Ring RPC reader (Ring RPC holds the auditor key and serves openings to granted readers) | Alice as sender, Bob's owner key and `u`, the asset, the amount and Alice's spent notes. | The same. |

### Adding an exit, a withdrawal or a default-ring spend

An exit pays a default-ring note, and its owner is public. A withdrawal pays SOL or a token to a public account.

| Leg | Public | Checked |
| --- | --- | --- |
| Exit to key `K` | `K` as the exit's owner | SPP's proof refuses `K` equal to Alice's key on a ring spend. |
| Withdrawal to `D` | `D`, the mint and the amount | All withdrawals of the transfer name one `D`, and the audit proof shows `D` differs from Alice. |
| Default-ring spend | Alice's identity as `default_owner_tag` | The auditor gets full openings of every spent note. |

Each leg puts one more key on chain. No check finds a `K` or a `D` that belongs to Alice under another key. Alice stays hidden only when no one links `K` and `D` to Alice and Alice spends no default-ring note.

## What the circuit proves

The program rebuilds the anonymous audit statement, the public values the proof binds, from the frame, the clock, the SPP tree and the accounts. The circuit binds three things:

1. **The sender to the spent notes**: every spent note is the hidden owner's and reopens SPP's `private_tx_hash`, the blinded hash over the spent note hashes and the output hashes that SPP's proof binds. The hidden owner differs from the payer, the configured co-signer and the withdrawal destination.
2. **Tags to streams**: each inbox or pair tag is `low128` of its stream digest at an index below 64. The ring data hash binds the slot secret and the tag.
3. **The auditor message to the transfer**: it seals `tx_viewing_sk` to the auditor, opens every output, and names every spent note by hash and 16-byte prefixes, or by full openings on an entry spend.

Not proven: no layer checks an exit owner or a withdrawal destination for a link to the hidden owner. The tags of change and of dummy padding outputs are free. The tag index can repeat across transfers. No proof shows the output owner holds `u`.

See [Anonymity breaks when its conditions fail](spec.md#anonymity-breaks-when-its-conditions-fail), [Repeated payment tags link payments](spec.md#repeated-payment-tags-link-payments), [The anchor dates a first contact](spec.md#the-anchor-dates-a-first-contact), [Streams](spec/crypto/hashing.md#anonymous-streams) and [Disclosure](spec/crypto/disclosure.md).

<aside>

**Important:** the payer and the Solana fee payer must not link to the hidden owner. Only the SPP payer is checked on chain, by the signer check and by its party identity. A sender draws each tag index from 64, so two transfers on one stream in one epoch publish equal tags with probability 1/64, and equal tags link them.

</aside>

## Code reading guide

1. **Rail selection**: `program-libs/interface/src/instructions/transact.rs:98`
    - `RingRail::of` maps the tag and the mode to a rail, and `DelegateTransact` on `Anonymous` fails.
2. **Payer-only signer**: `programs/custom-ring/src/instructions/transact/accounts.rs:118`
    - Any other SPP signer fails with `InvalidAnonymousSigner`. Line 164 builds the party identities, and `programs/custom-ring/src/instructions/transact/processor.rs:45` binds the epoch and the first-contact root.
3. **Withdrawal destination**: `program-libs/interface/src/instructions/anonymous_exit.rs:122`
    - Every withdrawal names one key. `identities` at line 175 hashes the three parties.
4. **Streams**: `program-libs/interface/src/codec/stream.rs:114`
    - `InboxKey::derive`, `PairKey::derive` at line 147 and `tag_epoch` at line 35.
5. **Anonymous audit**: `prover/circuits/audit/anonymous.go:115`
    - `anchor` at line 197, `assertTag` at line 238, `spend` at line 251. Line 192 leaves a change tag free.
6. **Delivery**: `prover/circuits/audit/delivery.go:53`
    - The body opens for `u`. Line 76 binds the owner to the disclosed owner key, and nothing binds `u` to it.
7. **Parties**: `prover/circuits/shared/parties.go:7`
    - Each nonzero party identity differs from the hidden owner.
8. **Wallet state**: `sdk-libs/client/src/operations/anonymous.rs:248`
    - `TagAllocation::allocate` at line 1388 picks the stream, `draw` at line 1434 the index. `by_rank` at line 216 orders the decoys.
9. **Ring address**: `sdk-libs/keys/src/ring_address.rs:97`
    - `Pairing::admits` at line 84 decides which first contacts anchor a pair.
10. **SPP hidden owner**: `zolana/prover/server/circuits/spp_transaction/custom/anonymous_eddsa.go:198` at `ff04c625c`
    - `ed25519.Verify` checks the owner's signature. In `AssertDefaultHiddenOwner` at `zolana/prover/server/circuits/spp_transaction/shared/signers.go:107`, line 126 publishes `default_owner_tag`, line 128 refuses an entry spend that also spends ring notes, and line 130 refuses an exit to the hidden owner on a ring spend.

### Notes

**Conditions anonymity rests on**

1. The payer and the Solana fee payer do not link to the hidden owner.
2. The transfer spends ring notes only.
3. No exit or withdrawal pays a key linked to the owner.
4. Each ring address goes to one sender and is never published.
5. The wallet runs its own indexer or trusts it, and the prover runs locally or in an attested TEE.
6. The anchor tree holds many anonymous outputs before the named root.
7. The rules admit many owners. An allow rule bounds every sender and recipient to the public allow list.
8. Public leg amounts and timing do not single out a spend.

[Anonymity breaks when its conditions fail](spec.md#anonymity-breaks-when-its-conditions-fail) gives each condition.

**What each observer learns**

1. Photon, the zolana SPP indexer: one address's inbox and pair tags per request, and the anchor with its 7 decoys in one request (`sdk-libs/client/src/operations/anonymous.rs:874`, `sdk-libs/sdk/src/operations/pipeline/anonymous.rs:437`).
2. Ring indexer: every call it forwards to Photon, and on a policy ring the members a client opens (`services/ring-indexer/src/rpc/server/mod.rs:42`, `services/ring-indexer/src/rpc/api.rs:164`).
3. Prover: the full witness, the hidden owner and every opening included (`prover/circuits/audit/anonymous.go:64`).
4. Ring RPC reader: what the auditor opens, once granted (`services/ring-rpc/src/operations/audit.rs:284`).
