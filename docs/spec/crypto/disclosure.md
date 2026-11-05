# Disclosure

A ring transfer opens to the auditor through one AES-256-CTR stream, the auditor message. Its envelope seals the transaction viewing secret and the count of spent notes. Its records open every published output slot. Recipient bodies, tags, replies and the sender bundle stay outside every proof. [Spec](../../spec.md) [Envelope](envelope.md)

## Verified audit recovery

Every published slot of a transfer whose proof verifies opens for the auditor from its own record. The record is the guarantee, whatever the slot's recipient body contains.

- A ring output, an exit and a dummy each have one record. An exit's record opens the created default-ring note, its owner key included.
- A spent ring note has no record. The auditor links its nullifier from an opening it already holds and the owner's enrolled secret. A note the auditor never opened stays unlinked until its opening arrives, and it withholds no output slot.
- A spent default-ring note opens in full in the envelope of an entry key, and no secret is disclosed.
- A wrong recipient body leaves the auditor's record unchanged. Ring RPC serves the owner its opening from that record, see [auditor fallback](../../design/audit-and-recovery.md#auditor-fallback).

## Discovery

Each published slot carries an owner tag. A non-exit slot's tag is an unproved hint: no proof constrains it, and SPP's external data hash binds only its bytes. A frame carries the low 8 bytes of a non-exit tag, and the program restores the 24 leading zero bytes before SPP reads it.

| Slot | Tag |
|---|---|
| Ring output, confidential frame | low 8 bytes of the recipient's `viewing_u` |
| Dummy, confidential frame | low 8 bytes of a fresh random key's `u` |
| Ring output, anonymous frame | low 8 bytes of `Poseidon(CRRT, CRDS_i)` |
| Change, anonymous frame | zero |
| Dummy, anonymous frame | low 8 bytes of `Poseidon(CRRT, s)`, `s` drawn uniform below `q` |
| Exit | SPP's 32-byte owner tag, which SPP's proof holds to the exit's owner |
| Sender bundle | `Poseidon(CRST, CRDS_m)`, 32 bytes |

`CRDS_i` is the [slot secret](hashing.md#slot-secret) that also keys slot `i`'s body. A wrong tag hides no decryptable note, because a full scan tries every body without a tag. [Wallet scanning](../../design/audit-and-recovery.md#wallet-scanning) states how a reader finds its notes.

## Auditor message

The auditor message is SPP's last message, under the auditor's `u` as its view tag. Its data is:

```text
0x04 || tx_viewing_u || envelope_ct || record_ct_0 .. record_ct_{m-1} || tail_ct_0 .. tail_ct_{m-1}
```

`tx_viewing_u` is SPP's `tx_viewing_pk` without its tag. Each record ciphertext has 105 bytes. The tails are present exactly when `has_data` is set, 64 bytes each.

`n` is the published input count, the frame's nullifier count. It is never the key capacity and never a private live count. The key's input class and entry flag, its output capacity `N`, `m`, `n`, `has_data`, the exit and bodiless bitmaps, each body length under `has_data` and `reply_len` fix every length. The program refuses a frame of any other length.

## Stream regions

The stream has one key, one nonce and one `CTREncrypt` call in the circuit over the capacity-sized plaintext. Each region is zero padded to a multiple of 16 bytes, so it starts on its own counter and no counter serves two regions. The key alone fixes every counter, so a reader decrypts slot `i` with no other slot. The frame carries only transmitted bytes, and padding and unpublished slots never leave the prover.

| Region | Start counter | Maximum blocks | Transmitted bytes |
|---|---|---|---|
| Envelope | `2` | `E` | `33`, or `41 + 200 n` on an entry key |
| Record of slot `i` | `R0 + 7 i`, `R0 = 2 + E` | `7` | `105` for `i < m` |
| Tail of slot `i` | `T0 + 4 i`, `T0 = R0 + 7 N` | `4` | `64` for `i < m` under `has_data` |

`E = ceil(33 / 16)` on a key without entry capacity, and `E = ceil((41 + 200 c) / 16)` on an entry key of input class `c`.

## Envelope plaintext

```text
tx_viewing_sk || u8(R)                                                  key without entry capacity
tx_viewing_sk || u8(R) || u64be(default_input_bits) || entry_input * n  entry key
entry_input = owner_key || fe32(nullifier_pk) || u64be(amount) || mint || fe32(blinding) || fe32(data_hash) || fe32(ring_data_hash)
```

`R` counts the spent notes among the published inputs. Dummies come last in SPP's order, so a nullifier at position `k < R` is a spend and one at `k >= R` is padding. Bit `k` of `default_input_bits` is set exactly when input `k` is a default-ring note. `entry_input_k` opens that note in 200 bytes and is all zero on every other input. `mint` is the 32-byte mint address, and the proof holds the input's asset to it.

## Spent notes

- A key without entry capacity refuses a default-ring input, since no evidence would open it.
- The auditor recomputes SPP's nullifier of a note from the opening it already read and the owner's secret from enrollment, or zero under the zero nullifier key, then matches SPP's published list. A match links the spend.
- No constraint binds a nullifier to an opening. A real nullifier with no match stays unresolved and never reads as padding.
- An entry input discloses its owner key, nullifier key, amount, mint, blinding and both data hashes, and no nullifier secret. Each input carries its own owner and key, so one frame spends default-ring notes of several owners.

## Records

```text
record = u8(kind) || u64be(amount) || owner_key || mint || fe32(nullifier_pk)   105 bytes
tail   = fe32(data_hash) || fe32(ring_data_hash)                                 64 bytes
```

| `kind` | Slot | Plaintext |
|---|---|---|
| `0` | dummy | all zero |
| `1` | ring output | the slot's opening |
| `2` | exit | the slot's opening |

The proof derives `kind` from the domain and ring id the slot's hash commits, so no prover choice passes a note as a dummy. `owner_key` is the raw key whose `solana_owner_identity` the commitment hashes, and `mint` the raw mint whose `hash_bytes` is its asset. The auditor names an owner and an asset with no directory. The record omits the blinding, which the sealed key derives. A tail is zero on a dummy, and a clear `has_data` holds both data hashes of every slot to zero.

## Recipient body

The SDKs seal one form on every frame, under `CRING/rcp` and the slot secret of the recipient's viewing key:

```text
fe32(blinding) || u64be(amount) || mint                                         72 bytes
|| u8(has_ring_data) || ring_data_hash? || (data_hash || application_data)?    only when either part is present
```

`ring_data_hash` follows when `has_ring_data` is `1`. `data_hash` and the application data follow when the note's `data_hash` is nonzero. The commitment covers both, so the reader needs them to rebuild it.

The body travels as SPP output data under scheme 10, `u16le(body_len) || body || reply`. No proof constrains it. A recipient rebuilds the commitment under its enrolled nullifier key, then under `ZERO_NULLIFIER_PUBKEY`, and accepts the note only on a match. A rebuilt commitment establishes ownership, because the body names no key. A dummy carries 72 random bytes. A slot in the bodiless bitmap carries no SPP data, and an exit carries zolana's scheme 3 body instead.

## Reply metadata

A frame opts in with `REPLY_METADATA`, on an anonymous frame only. The reply follows its body inside the slot's scheme 10 data, under `CRING/rpl` and the same slot secret:

```text
viewing_u || owner_key || nullifier_pk || wincode(Data), zero padded to reply_len
```

`reply_len` is one length per frame, at least 97. Every body-bearing slot carries one, and a slot with no reply or a dummy carries random bytes of that length. SPP's external data hash binds the bytes, and no proof reads their meaning. A reply is an unauthenticated claim about the sender. A reader never turns it into a verified sender identity.

## Sender bundle

Scheme 9 is the first SPP message of an anonymous frame, under `CRING/snd` and the slot secret at `i = m` of the sender's viewing key:

```text
mint0 || u64be(amount0) || u64be(amount1) || output_seed || recipient_u * m
```

The bundle has `80 + 32 m` bytes. `mint0` and `amount0` are slot 0's when slot 0 is change, else zero. `amount1` is slot 1's when slot 1 is change, else zero, and that slot's asset is native SOL. `recipient_u_i` is the viewing key the sender sealed slot `i`'s body to, and zero on change, exit and dummy. The reader rebuilds change at slots 0 and 1 from these cells, its own address and `TXOB(n0, output_seed, i)`, and accepts a slot only when its commitment rebuilds.

## Opening a transfer

1. The auditor computes `X25519(auditor_sk, tx_viewing_u)`, the salted [stream secret](envelope.md#shared-secret) and the stream, then recovers `tx_viewing_sk`, `R` and any entry evidence from the envelope.
2. It derives `seed_out = TXOS(n0, CRBS(tx_viewing_sk, salt))` and each blinding `TXOB(n0, seed_out, i)`. No frame field carries `seed_out`.
3. It decrypts the record of slot `i` at its counter, and its tail under `has_data`.
4. It rebuilds slot `i`'s commitment from the record, the tail, the blinding, the ring id on kind `1` or zero on kind `2`, and the frame's tree id, and accepts it only when it equals the published hash at `i`. A kind `0` slot rebuilds as SPP's dummy hash under its blinding. A record moved to another slot rebuilds nothing.
5. It links each nullifier below `R` that is not a default-ring input, see [spent notes](#spent-notes).

## Layout

| Bit value | Name | Set when |
|---|---|---|
| 1 | `has_data` | the frame carries one tail per published slot |
| 2 | `entry` | the frame selects a key with entry capacity |

The layout value is `has_data | entry << 1`. The circuit decomposes it into these two bits and holds `entry` to the key's entry capacity.

## Deposits and merges

A deposit seals one opening record per occupied slot, and a merge seals one opening record of its output:

```text
opening_record = record || 7 zero bytes || fe32(secret)   144 bytes
```

The secret is the deposit note's blinding, or the merge's seed. No envelope key derives either blinding, so the record seals what rebuilds it. The auditor rebuilds a merged note's blinding as `TMOB(seed, n0)`. A merge's ring proof opens no input, since SPP's merge proof ties every input to the output's owner, asset and sum. [Envelope uses](envelope.md#envelope-uses) states the keys and counters.
