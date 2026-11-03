# Disclosure

A ring transfer opens to the auditor through one AES-256-CTR stream and its delivered bodies. The stream's envelope region seals the transaction viewing secret and, off the signer rail, names the spent notes. Its record regions open the outputs that carry no delivered body. [Spec](../../spec.md) [Envelope](envelope.md)

## Verified audit recovery

Every slot of a transfer whose proof verifies opens for the auditor. One ring disclosure ciphertext per slot is the guarantee.

- Anonymous recipient and sender ciphertexts and exit recipient bodies are zolana ciphertexts, and no ring proof binds them.
- The signer rail discloses no spent note.
- Tracing by prefix can stay ambiguous or unseen. Several ring notes can carry one prefix, and the auditor can lack the note a prefix or `hash_0` names. An unseen note withholds no output slot.
- A key escrow slot needs its owner's nullifier key to rebuild its commitment. Until the auditor reads the owner's escrow record, the slot gives the proven owner key, amount and blinding, and the asset of an exit. A delivered body omits the asset, so the asset of a ring output stays unknown until the key arrives.
- Ring RPC derives a note's nullifier from a secret nullifier key to decide that the note is spendable. It decides this only for an owner whose key it holds.

## Auditor message

The auditor message data, under the auditor view tag, is:

```text
0x04 || eph_u || envelope_ct || record_ct...
```

`record_ct...` holds the records of the slots that have one, in slot order. A delivered body stays in the slot frame under scheme 10, its length fixed by the layout's key escrow bit. The zolana scheme 1 body of an anonymous output stays in its slot.

`n` is the published input count, the frame's nullifier count. It is never the key capacity and never a private live count. Family, layout, `n_out`, `n`, the exits bitmap and the rail bits fix every length. The program refuses a frame of any other length.

## Stream regions

The stream has one key, one nonce and one `CTREncrypt` call in the circuit over the capacity-sized plaintext. Each region is zero padded to a multiple of 16 bytes, so it starts on its own counter and no counter serves two regions. The prover and the readers use a keystream. The frame carries only transmitted bytes, and padding and unused ranges never leave the prover.

| Region | Start counter | Maximum blocks | Transmitted bytes |
|---|---|---|---|
| Envelope | `2` | `2 + E_max(key)` | `32 + evidence_len` |
| Record of slot `i` | `R0 + i * R`, `R0 = 2 + 2 + E_max(key)` | `R(family)` | the record length of the slot's kind, none for a delivered slot |

`E_max(key)` is `ceil(max_evidence_len(key) / 16)` at the key's input class `c`:

| Key | `max_evidence_len` |
|---|---|
| Confidential family | `16 * c` |
| Anonymous, commitment key | `32 + 16 * (c - 1)` |
| Anonymous, entry key | `64 + 72 * c` |

`R(family)` is 7 on the anonymous family and 5 on the confidential family.

## Envelope plaintext

The envelope plaintext is `tx_viewing_sk || evidence`. `prefix16` is the first 16 bytes of a big-endian hash.

| Rail or key | Evidence |
|---|---|
| Signer rail | empty |
| In-proof and authority rails | `prefix16(input_hash_i)` for `i < n` |
| Anonymous, commitment key | `fe32(input_hash_0) \|\| prefix16(input_hash_i)` for `1 <= i < n` |
| Anonymous, entry key | `sender_key \|\| fe32(sender_nullifier_pk) \|\| (u64be(amount) \|\| fe32(asset) \|\| fe32(blinding)) * n` |

Slots at or past `n` stay absent. Spent notes come first in SPP's order and published dummies follow as zeros, so entry k names nullifier k.

## Spent notes

- The commitment key discloses `hash_0`, the full hash of the first spent note, and the 16-byte prefix of every other.
- The auditor finds `hash_0` among the notes it opened before and matches every prefix among the sender's ring notes. Several matches leave candidates, and no match leaves the input unseen with its hash or prefix.
- While `hash_0` is unseen the transfer names no sender, because no opened note binds the owner key. Its outputs open, and the auditor matches each prefix among all the ring notes it opened. A later read with the note names the sender and opens the input.
- The in-proof and authority rails disclose a prefix for each spent note. The auditor matches each among the ring notes it opened, and no match leaves the input unseen.
- The entry key spends default-ring notes, which the auditor never opened. It discloses every spent note's amount, asset and blinding, and the sender's key and nullifier key. The circuit holds every entry input to that one nullifier key.

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

| Bit | Name | Set when |
|---|---|---|
| 1 | none | always clear, every key refuses it |
| 2 | key escrow | the ring is in `ConfidentialEscrow` mode. Bodies and exit records omit the nullifier key, and the escrow records give it. |
| 4 | reserved | always clear, every key refuses it |
| 8 | full openings | an anonymous transfer spends default-ring notes |

The layout value is `key_escrow << 1 | full_openings << 3`. `exits_bitmap` is the one record of exits. The confidential family varies key escrow and pins full openings to `0`. The anonymous family's commitment layout pins both to `0`. Its entry layout pins full openings to `1` and key escrow to `0`.

## Merge disclosure

Only a merge uses a field pad. A merge seals a fresh 32-byte disclosure key under `CRING/mrg1` and masks its fields with:

```text
seed  = Poseidon(CR_MD, PackBytesBE(disclosure_key), right_align(salt))
pad_i = Poseidon(seed, i)
plaintext = owner_key || fe32(nullifier_pk) || mint || u64be(amount) || fe32(output_blinding) || fe32(input_hash) × width
fields    = pack_left31(plaintext) + pad
```

The salt is the SPP merge output salt. The field count is 13 at width 8 and 30 at width 24.
