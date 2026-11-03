# Disclosure

A ring transfer opens to the auditor through one AES-256-CTR stream and its delivered bodies. The stream's envelope region seals the transaction viewing secret and names the spent notes. Its record regions open the outputs that carry no delivered body. [Spec](../../spec.md) [Envelope](envelope.md)

## Verified audit recovery

Every published slot of a transfer whose proof verifies opens for the auditor. One ring disclosure ciphertext per slot is the guarantee.

- An exit's scheme 3 recipient body is a zolana ciphertext, and no ring proof binds it.
- An evidence entry can name a note the auditor has not opened. An unseen note withholds no output slot.
- A key escrow slot needs its owner's nullifier key to rebuild its commitment. Until the auditor reads the owner's escrow record, a delivered slot gives the proven owner key, amount and blinding. An exit gives its asset and amount, its blinding from `seed_out`, and its owner from the owner key SPP publishes. A delivered body omits the asset, so the asset of a ring output stays unknown until the key arrives.

## Discovery

The proof holds each anonymous tag to one of these forms:

```text
recipient_tag_i = Poseidon(CRRT, CRDS_i)     live recipient
bundle_tag      = Poseidon(CRST, CRDS_m)     sender bundle
dummy_tag       = Poseidon(CRRT, s)          hidden dummy, s a witness
```

`CRDS_i` is the [slot secret](hashing.md#slot-secret) the body already proves, and no second agreement runs. A change slot, an exit and an omitted slot chain a zero cell, and the program refuses a nonzero tag on change. An exit's `owner_tag` stays its scheme 3 owner key. `recipient_tag_chain` binds each cell and the bundle tag.

The preimage constrains a dummy tag and does not prove random sampling. It stops a sender selecting an arbitrary target tag without finding a preimage. It does not stop deliberate encoding through witness selection, so a dummy tag can carry information the sender chooses.

The proof shows what a tag is, and it does not show that a reader found it. [Wallet scanning](../../design/audit-and-escrow.md#wallet-scanning) states how a reader finds its notes.

## Auditor message

The auditor message data, under the auditor view tag, is:

```text
0x04 || eph_u || envelope_ct || record_ct...
```

`record_ct...` holds the records of the slots that have one, in slot order. A delivered body stays in the slot frame under scheme 10, its length fixed by the layout's key escrow bit. A recipient body stays in its slot under scheme 11.

`n` is the published input count, the frame's nullifier count. It is never the key capacity and never a private live count. Family, layout, `N`, `m`, `n`, the exit and change bits and `reply_len` fix every length. The program refuses a frame of any other length.

## Stream regions

The stream has one key, one nonce and one `CTREncrypt` call in the circuit over the capacity-sized plaintext. Each region is zero padded to a multiple of 16 bytes, so it starts on its own counter and no counter serves two regions. The prover and the readers use a keystream. The frame carries only transmitted bytes, and padding and unused ranges never leave the prover.

| Region | Start counter | Maximum blocks | Transmitted bytes |
|---|---|---|---|
| Envelope | `2` | `2 + E_max(key)` | `32 + evidence_len` |
| Record of slot `i` | `R0 + i * R`, `R0 = 2 + 2 + E_max(key)` | `R(family)` | the record length of the slot's kind, none for a delivered slot |

`E_max(key)` is `ceil(max_evidence_len(key) / 16)` at the key's input class `c`:

| Key | `max_evidence_len` |
|---|---|
| Confidential family | `32 * c` |
| Anonymous, commitment key | `32 * c` |
| Anonymous, entry key | `64 + 104 * c` |

`R(family)` is 7 on the anonymous family and 5 on the confidential family.

## Envelope plaintext

The envelope plaintext is `tx_viewing_sk || evidence`.

| Rail or key | Evidence |
|---|---|
| Signer, in-proof and authority rails | `fe32(input_hash_i)` for `i < n` |
| Anonymous, commitment key | `fe32(input_hash_i)` for `i < n` |
| Anonymous, entry key | `sender_key \|\| fe32(sender_nullifier_pk) \|\| (fe32(input_hash_i) \|\| u64be(amount) \|\| fe32(asset) \|\| fe32(blinding)) * n` |

Slots at or past `n` stay absent. A published dummy reads as zeros. Spent notes come first in SPP's order, so entry `k` names nullifier `k`.

## Spent notes

- Every rail discloses each spent note's full hash, so one evidence entry fits one note.
- The auditor matches each hash among the ring notes and merge outputs it opened. No match leaves the input unnamed with its hash, and it holds the row as unresolved.
- Under the commitment key an unnamed first note leaves the sender unnamed, because only that note binds the owner key. Its outputs open, and a later read with the note names the sender.
- The entry key serves a spend of default-ring notes, which the auditor never opened. It discloses every spent note's amount, asset and blinding, and the sender's key and nullifier key. The circuit holds every entry input to that one nullifier key.
- The circuit does not hold an entry input to ring id 0. The reader tries the ring id and the default id against each hash.

## Records

| Slot kind | Record plaintext | Bytes |
|---|---|---|
| Anonymous ring output | `owner_key \|\| fe32(asset) \|\| u64be(amount) \|\| fe32(nullifier_pk)` | 104 |
| Exit | `fe32(asset) \|\| u64be(amount) \|\| fe32(nullifier_pk)`, the last field omitted under key escrow | 72 or 40 |

An exit's owner stays where zolana publishes it.

## Delivered body

```text
fe32(blinding) || u64be(amount) || owner_key || fe32(nullifier_pk)
```

The last field is omitted under key escrow, so a body has 72 bytes under key escrow and 104 otherwise. The secret is the [slot secret](hashing.md#slot-secret) under `CRING/bdy1`. The recipient and the auditor read the same bytes.

The body omits the asset. A reader tries each asset it knows against the commitment. The recipient also compares the decrypted owner key and nullifier key with its own before it accepts the note. A rebuilt commitment alone does not establish ownership. Under key escrow the body has no nullifier key, so the recipient compares the owner key and rebuilds the commitment with its own nullifier key.

## Recipient body

Scheme 11 keys each anonymous live ring slot, under `CRING/rcp1` and the slot secret of the owner's record-bound viewing key:

```text
fe32(blinding) || u64be(amount) || mint
```

The body has 72 bytes. `mint` is the 32-byte address, and the proof holds the slot's asset to its chunks. The recipient rebuilds the commitment with its registered nullifier key, then with `ZERO_NULLIFIER_PUBKEY`. A rebuilt commitment establishes ownership, because the body names no key. A change or exit slot has no body. A hidden dummy carries 72 random bytes.

## Reply metadata

A frame opts in with `REPLY_METADATA`, on the anonymous rail only. The reply follows its body in the slot, under `CRING/rpl1` and the same slot secret:

```text
viewing_u || owner_key || nullifier_pk || wincode(Data), zero padded to reply_len
```

`reply_len` is one length per frame, at least 97. Every body-bearing slot carries one, and a slot with no reply or a hidden dummy carries random bytes of that length. The statement binds the bytes through `reply_digest` and proves nothing about their meaning. A reply is an unauthenticated claim about the sender. A reader never turns it into a verified sender identity.

## Sender bundle

Scheme 12 is the first SPP message, under `CRING/snd1` and the slot secret at `i = m` of the sender's record-bound viewing key:

```text
mint0 || u64be(amount0) || u64be(amount1) || output_seed || recipient_u * m
```

The bundle has `80 + 32 m` bytes. `mint0` and `amount0` are slot 0's when bit 0 of `change_bits` is set, else zero. `amount1` is slot 1's when bit 1 is set, else zero, and that slot's asset is native SOL. `recipient_u_i` is the record-bound key on a live slot that is not change, and zero on change, exit and dummy. The reader rebuilds change from `change_bits`, its own address and `TXOB(n0, output_seed, i)`.

## One ring disclosure ciphertext per output

| Slot kind | Ciphertext | Bytes |
|---|---|---|
| Confidential ring output | delivered body | 72 or 104 |
| Anonymous ring output | auditor record | 104 |
| Exit, either family | auditor record | 72 or 40 |
| Hidden dummy, confidential family | random delivered body | 72 or 104 |
| Hidden dummy, anonymous family | auditor record over a zero plaintext | 104 |

The anonymous family pins key escrow to `0`, so its exit record has 72 bytes.

## Opening a transfer

1. The auditor computes `X25519(auditor_sk, eph_u)`, derives the stream and recovers `tx_viewing_sk` from the envelope.
2. It derives `seed_out = TXOS(n0, CRBS(tx_viewing_sk, salt))` and each blinding `TXOB(n0, seed_out, i)`. No frame field carries `seed_out`.
3. It rebuilds each slot secret from `tx_viewing_sk` and the published `u`, then opens each delivered body. A slot whose commitment is the dummy hash under its blinding opens as a hidden dummy.
4. It opens each record at its counter from the stream.
5. It rebuilds each output commitment from the opened fields and the blinding. Under key escrow the escrow records give the output nullifier keys, and a slot whose record the auditor has not read keeps its opened fields without a rebuilt commitment.

## Layout bits

| Bit value | Name | Set when |
|---|---|---|
| 1 | none | always clear, every key refuses it |
| 2 | key escrow | the ring is in `ConfidentialEscrow` mode. Bodies and exit records omit the nullifier key, and the escrow records give it. |
| 4 | reserved | always clear, every key refuses it |
| 8 | full openings | the frame selects the entry key |

The layout value is `key_escrow << 1 | full_openings << 3`. `exits_bitmap` is the one record of exits. The confidential family varies key escrow and pins full openings to `0`. The anonymous family's commitment layout pins both to `0`. Its entry layout pins full openings to `1` and key escrow to `0`.

## Merge disclosure

Only a merge uses a field pad. A merge seals a fresh 32-byte disclosure key under `CRING/mrg1` and masks its fields with:

```text
seed  = Poseidon(CR_MD, PackBytesBE(disclosure_key), right_align(salt))
pad_i = Poseidon(seed, i)
plaintext = fe32(input_hash_0) || .. || fe32(input_hash_{width-1})
fields    = pack_left31(plaintext) + pad
```

The salt is the SPP merge output salt. Slot `i` of the list is slot `i` of SPP's private transaction hash, and a dummy slot reads 32 zero bytes. The field count is 9 at width 8 and 25 at width 24. The disclosure names no owner, mint or amount. The auditor inherits them from the opened inputs and records the output with their sum.
