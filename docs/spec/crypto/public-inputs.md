# Public inputs

Every ring proof has one public input. It is the fold of a statement its verifier rebuilds, the program or, for register key, Ring RPC. A prover supplies none of the elements the verifier can derive. Element lists are in order. [Spec](../../spec.md) [Hashing](hashing.md)

| Statement | Fold | Elements | Verified by |
|---|---|---|---|
| Transfer, confidential family | `HashChain4` | `41 + N` | `Transfer`, `AuthorityTransfer` |
| Transfer, anonymous family | `HashChain4` | 45 | `Transfer` |
| Apply | `HashChain4` | 8 | Storage `Update`, `UpdateImmediate` |
| Register key | `HashChain4` | 8 | Ring RPC writer, off chain |
| Deposit | `HashChain` | 44 | `Deposit` |
| Merge | `HashChain` | 18 | `Merge` |

## Transfer

Use [Proof composition](../../design/proof-composition.md) to review the constraint handoffs and program-derived fields.

One proof covers the audit, the policy, the withdrawal exemption and, on the anonymous family, recipient delivery. The confidential family serves the signer, in-proof and authority rails. The anonymous family serves the anonymous rail, with the commitment or entry layout by the head's `layout`.

`n` is the frame's nullifier count and `m` its published slots. `N` is the key's output capacity and `S` its signer slots. Per-slot chains are zero-filled to `N`, so `output_count` alone carries `m`.

```text
[ CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, envelope_digest, salt, layout,
  in_proof, delegate,                 confidential family only
  exempt, approval_required,
  output_count,
  output_chain,
  output_ciphertext_chain,
  recipient_key_chain,                confidential family only
  recipient_body_chain,               anonymous family only
  recipient_tag_chain,                anonymous family only
  change_bitmap,                      anonymous family only
  sender_bundle_digest,               anonymous family only
  input_count, exits_bitmap, private_tx_hash,
  sender,                             confidential family only
  party_0, party_1, party_2,          anonymous family only
  signer_count, signer_chain,
  policy_hash, own_root, curator_root,
  recipient_0 .. recipient_{N-1},     confidential family only
  (asset_k, net_k, gross_k) per public slot,
  withdrawal_hash,
  reply_digest,                       anonymous family only
  length,                             the element count, the count and the version included
  3 ]                                 TRANSFER_STATEMENT_VERSION
```

- The head's `layout` bits are `key_escrow` and `full_openings` of [Layout bits](disclosure.md#layout-bits). `key_escrow` equals `mode == ConfidentialEscrow`.
- `in_proof` is the frame's `OWNER_IN_PROOF` flag, and `delegate` is the `AuthorityTransfer` tag. `exempt` is the frame's `EXEMPT` flag. `approval_required` is its `APPROVAL_REQUIRED` flag, refused on the authority rail.
- `output_count` is `right_align(m)`.
- `input_count` is `right_align(n)`. `exits_bitmap` is the right-aligned bitmap with bit `i` set when slot `i` is an exit. The program writes both from the frame. The circuit holds the input count to its evidence selection and derives the bitmap from the opened slots.
- `sender` is `solana_owner_identity` of the framed owner key on the in-proof rail, and zero on the signer and authority rails.
- The party identities are `solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, each `0` when absent.
- `signer_count` is the number of distinct keys in the SPP owner signer run, deduplicated by first occurrence. `signer_chain` is `HashChain4` of their identities in that order, zero-filled to `S`, and `0` when the count is `0`. The in-proof, authority and entry rails bind count `0` and chain `0`.
- `policy_hash` is the ring account's written hash, zero on an audit-only ring. `own_root` and `curator_root` are the registry roots at the frame's revisions. `own_root` is zero when no registry is read, and an anonymous ring always reads one. `curator_root` is zero without a curator.
- `recipient_o` is output `o`'s owner identity from the frame under a policy, zero off one, for a dummy slot and past `m`.
- A public slot holds SPP's asset field and the signed net, `right_align(net)` when positive or `q - |net|` when negative. It also holds the gross withdrawal of the asset as `right_align` of a u128, deposits excluded. Slots past the used ones are zeros. Under `exempt` the circuit bounds every gross to u64 and to the asset's own-record `withdrawal_threshold`.
- `withdrawal_hash` is the policy withdrawal hash below. The count and the nonzero version close the chain, and a statement of another length or layout hashes apart.

The head has 12 elements:

| # | Element | Source |
|---|---|---|
| 0 | `CRTX` | constant |
| 1 | `n0` | the frame's first nullifier, SPP nullifier `0` |
| 2 | `ring_id` | `hash_bytes` of the executing program id |
| 3, 4 | `pack_be(0x04 \|\| tx_viewing_u)` | frame, SPP `tx_viewing_pk` |
| 5, 6 | `pack_be(auditor_pubkey)` | ring policy |
| 7, 8 | `pack_be(0x04 \|\| eph_u)` | frame |
| 9 | `digest(envelope_ct)` | frame |
| 10 | `right_align(salt)` | frame, SPP salt |
| 11 | `right_align(layout)` | the frame's flags, bit values `1` and `4` clear |

The chains over the slots, each zero past `m`:

- `output_chain = HashChain4(hash_i)`, a hidden dummy's hash included.
- `output_ciphertext_chain = HashChain4(hash_bytes(ct_i))`, in slot order. `ct_i` is the slot's [ring disclosure ciphertext](disclosure.md#one-ring-disclosure-ciphertext-per-output). Layout and exits bitmap fix each length, so `hash_bytes` needs no length, and the program refuses a length off the table.
- `recipient_key_chain = HashChain4(pack_be(u_i))`, two zero fields on an exit, confidential family only.
- `recipient_body_chain = HashChain4(hash_bytes(body_i))`, zero on a change or exit slot, anonymous family only. A hidden dummy's body hashes as sent.
- `recipient_tag_chain = HashChain4(tag_0 .. tag_{N-1}, bundle_tag)`, `N + 1` cells, zero on a change or exit slot and past `m`, anonymous family only. [Discovery](disclosure.md#discovery) gives each tag's form.

`withdrawal_hash = HashChain4([CRPW, right_align(count), (owner, asset, right_align(amount)) per withdrawal leg])`, in settlement order under a policy and over no leg otherwise. A SOL leg's owner is `solana_owner_identity(recipient)`, and an SPL leg's owner is the identity of the token account's owner.

The frame values:

- `change_bitmap` is the frame's `change_bits`. The circuit derives each bit from the exact address match.
- `sender_bundle_digest = digest(bundle)`, and its length follows `m`.
- `reply_digest = digest(reply region)`, and `0` without `REPLY_METADATA`. The circuit carries it as a public element. It binds presence, length and bytes and proves nothing about meaning.

No zolana ciphertext enters the statement, an exit's scheme 3 body included. The circuit holds every spent UTXO to its rail's owner predicate and reopens SPP's `private_tx_hash` over the same inputs and outputs with no address input. `private_tx_blinding` stays private.

## Apply

```text
[ CRAP, old_root, new_root, right_align(old_next_index), right_align(new_next_index),
  chain_start, chain_end, right_align(count) ]
```

The storage program supplies `old_root` as the registry's newest root, `old_next_index`, `chain_start = HashChain4([APPLY_RECORDS, hash_bytes(registry), revision])`, `chain_end` as the chain over the update's writes and `count` as their number. Only `new_root` and `new_next_index` come from the `ApplyRecordsIxData`.

## Register key

```text
[ CRRG, solana_owner_identity(owner), nullifier_pk,
  pack_be(auditor_pubkey), pack_be(0x04 || eph_u), hash_bytes(ciphertext) ]
```

The statement has 8 elements and no registry root.

## Deposit

```text
context_hash = HashChain([ hash_bytes(program id), hash_bytes(tree),
                           right_align(len(spp_data) as u64), HashChain(right-aligned 31-byte chunks of spp_data) ])
statement    = HashChain([ CRDP, context_hash, right_align(count), right_align(anonymous),
                           (owner_utxo_hash_i, hash_bytes(capsule ciphertext_i)) × 8,
                           pack_be(auditor_pubkey), pack_be(eph_pk),
                           right_align(key_escrow), registry_root, curator_root, policy_hash,
                           (asset_i, right_align(amount_i)) × 8 ])
```

`spp_data` is the forwarded SPP data from its tag byte `18`. Slots past `count` are zero. `anonymous` is `mode == Anonymous`. `key_escrow` is `mode == ConfidentialEscrow`. `registry_root` is the own root at the prefix's `own_revision` in `ConfidentialEscrow` mode or on a policy ring, else `0`. `curator_root` is the curator root at the prefix's `curator_revision` when a policy source names a curator, else `0`. `policy_hash` is the ring account's written hash on a policy ring, else `0`. `asset_i` is the SPP asset field of entry `i`'s group, `SOL_ASSET_FIELD` or `hash_bytes(mint)`, and `amount_i` its amount.

## Merge

```text
[ CRMG, private_tx_hash, output_utxo_hash, n0, ring_id,
  pack_be(auditor_pubkey), pack_be(eph_pk), hash_bytes(ciphertext), right_align(salt),
  HashChain4(disclosure fields), right_align(input_count),
  party_0, party_1, party_2, right_align(key_escrow), member_registry_root ]
```

The salt is the SPP merge output salt. `input_count` is the merge's nullifier count, and a slot below it can be a hidden dummy. The party identities are the payer, the signing co-signer and `0`. `key_escrow` is `mode == ConfidentialEscrow`, and then `member_registry_root` is the own root at the merge's `own_revision`, else `0`. SPP's merge proof binds the same `private_tx_hash` and nullifiers.
