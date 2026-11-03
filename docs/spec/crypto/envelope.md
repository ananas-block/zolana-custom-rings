# Envelope

The envelope seals a secret to the ring's X25519 auditor key. A ring uses it for a transfer's auditor stream, a member's nullifier secret, deposit openings and the merge disclosure key. The stream schedule also keys every delivered body, recipient body, reply and sender bundle from a slot secret. [Spec](../../spec.md) [Hashing](hashing.md) [Disclosure](disclosure.md)

The ring program verifies the transfer, deposit and merge proofs, so the ciphertext's hash in the statement fixes the plaintext. Only Ring RPC verifies the register key proof, off chain. A proof under key escrow takes that ciphertext's hash as a private input and relies on the Ring RPC check.

## Key encoding

- A tagged X25519 key is `0x04 || u`, 33 bytes, with `u` the canonical 32-byte little-endian coordinate below `2^255 - 19`.
- `Initialize` refuses an auditor key whose `u` is one of the 5 low-order values. The program supplies the auditor key from the ring policy, so a prover cannot pick the recipient.
- The auditor view tag is `u` without the tag byte.
- Secret scalars are clamped as RFC 7748. The audit circuit asserts that `tx_viewing_sk` is clamped.

## Shared secret

```text
dh     = X25519(eph_sk, auditor_u)                   // canonical u, all-zero output refused
eph_pk = 0x04 || X25519(eph_sk, 9)
secret = Poseidon(CR_S, pack_be(dh), pack_be(eph_pk), pack_be(auditor_pk))   // 7 inputs
```

The circuit does not prove that `eph_sk` is fresh. A reused `eph_sk` under one auditor key repeats the keystream. The SDKs draw a fresh salt and a fresh `eph_sk` per build, so a rebuilt transfer never reuses a key and nonce with another plaintext.

## Stream schedule

Every ring encryption line except merge uses one schedule, with a 10-byte label as a parameter:

```text
head  = Poseidon(right_align(label || 0x00), secret)
tail  = Poseidon(right_align(label || 0x01), secret)
key   = low31_be(head) || low13_be(tail)[0]          // 32 bytes
nonce = low13_be(tail)[1..13]                        // 12 bytes
ciphertext = AES-256-CTR(key, nonce || u32be(counter), plaintext), counter from 2
```

`lowN_be` takes the low `N` bytes of the canonical field value. The label enters the first Poseidon input, so one secret gives one key per label.

| Label | Line | Secret |
|---|---|---|
| `CRING/adt1` | auditor stream | shared secret above |
| `CRING/bdy1` | delivered body, scheme 10 | [slot secret](hashing.md#slot-secret) at `i` |
| `CRING/rcp1` | recipient body, scheme 11 | slot secret at `i` |
| `CRING/rpl1` | reply metadata | the secret of slot `i`'s body |
| `CRING/snd1` | sender bundle, scheme 12 | slot secret at `m` under the sender's viewing key |
| `CRING/nfk1` | register key | shared secret above |
| `CRING/dep1` | deposit | shared secret above |

One label per ciphertext kind gives each kind its own key and nonce, so a reply never restarts the body's counter. A live recipient's tag and the bundle tag are each one more Poseidon output of the secret that keys that ciphertext, under its own [domain](hashing.md#domain-tags). An exit's scheme 3 body takes zolana's [AES Key derivation](../../../zolana/docs/spec.md#aes-key-derivation) outside every circuit.

## Merge schedule

The merge envelope uses the zolana verifiable encryption schedule under `CRING/mrg1`:

```text
siloed = Poseidon(TMSI, secret, PackBytesBE(label)[0])
key    = low16_be(Poseidon(TMSL, siloed)) || low16_be(Poseidon(TMSK, siloed))
nonce  = low12_be(Poseidon(TMSN, siloed))
ciphertext = AES-256-CTR(key, nonce || u32be(counter), plaintext), counter from 2
```

The first Poseidon input is `TMSI` here and a right-aligned label in the stream schedule, so the two schedules never give one key from one secret.

## Envelope uses

No line has an authentication tag. Integrity comes from the statement.

| Use | Schedule | Plaintext | Statement binds |
|---|---|---|---|
| Auditor stream | `CRING/adt1` | `tx_viewing_sk`, evidence and records of [Disclosure](disclosure.md) | `pack_be` of both tagged keys and of `tx_viewing_pk`, `digest(envelope_ct)`, `hash_bytes(record)` through `output_ciphertext_chain` |
| Delivered body | `CRING/bdy1`, slot secret | the [delivered body](disclosure.md#delivered-body) | `hash_bytes(body)` through `output_ciphertext_chain`, `pack_be(u)` through `recipient_key_chain` |
| Recipient body | `CRING/rcp1`, slot secret | the [recipient body](disclosure.md#recipient-body) | `hash_bytes(body)` through `recipient_body_chain` |
| Reply metadata | `CRING/rpl1`, slot secret | the [reply](disclosure.md#reply-metadata) | `digest` of the reply region, as `reply_digest` |
| Sender bundle | `CRING/snd1`, slot secret | the [sender bundle](disclosure.md#sender-bundle) | `digest(bundle)`, as `sender_bundle_digest` |
| Register key | `CRING/nfk1` | `0x00 \|\| nullifier_secret`, 32 bytes | `pack_be` of both tagged keys, `hash_bytes(ciphertext)` |
| Deposit | `CRING/dep1` | per note `fe32(owner_hash) \|\| fe32(blinding) \|\| owner_key`, 96 bytes | `pack_be` of both tagged keys, `hash_bytes` of each 96-byte slot |
| Merge | merge schedule | the 32-byte disclosure key of [Merge disclosure](disclosure.md#merge-disclosure) | `pack_be` of both tagged keys, `hash_bytes(ciphertext)` |

The deposit batch is one contiguous stream under one `eph_sk`, slot `i` at counter `2 + 6i`. The deposit owner key is the key whose `solana_owner_identity` is the note's `owner_pk_hash`.

## Deposit capsule

Each SPP deposit entry's ciphertext starts with a capsule the program parses:

```text
magic       "CRDEP001"
slot_index  u8, below 8, equal to the entry's position
eph_pk      [33], tag 0x04, equal across the batch
ciphertext  [96], bytes 96 i .. 96 i + 96 of the batch stream
recipient   the rest, the recipient's RingDepositPlaintext ciphertext, not proven
```

The capsule header is 138 bytes. The auditor opens the batch from one ECDH and checks each owner hash and blinding against the published `owner_utxo_hash`.
