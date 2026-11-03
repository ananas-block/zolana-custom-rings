# Public inputs

Every ring proof has one public input. It is the fold of a statement the program rebuilds from chain state and instruction data. A prover supplies none of the elements the program can derive. Element lists are in order. [Spec](../../spec.md) [Hashing](hashing.md)

| Statement | Fold | Elements | Verified by |
|---|---|---|---|
| Transfer, confidential family | `HashChain4` | `37 + n_out` | `Transfer`, `AuthorityTransfer` |
| Transfer, anonymous family | `HashChain4` | 35 | `Transfer` |
| Apply | `HashChain4` | 8 | Storage `Update`, `UpdateImmediate` |
| Register key | `HashChain4` | 8 | Ring RPC writer, off chain |
| Deposit | `HashChain` | 44 | `Deposit` |
| Merge | `HashChain` | 17 | `Merge` |

## Transfer

Use [Proof composition](../../design/proof-composition.md) to review the constraint handoffs and program-derived fields.

One proof covers the audit, the policy and the withdrawal exemption of a transfer. The
confidential family serves the signer, in-proof and authority rails, the anonymous family the
anonymous rail with the commitment or the entry disclosure by the head's `layout`.

```text
[ CRTX, n0, ring_id, txpk0, txpk1, aud0, aud1, eph0, eph1, sealed_hash, salt, layout,
  in_proof, delegate,                 confidential family only
  exempt, approval_required,
  output_chain,
  body_chain, recipient_key_chain,    confidential family only
  disclosure_chain, private_tx_hash,
  sender,                             confidential family only
  party_0, party_1, party_2,          anonymous family only
  policy_hash, own_root, curator_root,
  recipient_0 .. recipient_{n_out-1}, confidential family only
  (asset_k, net_k, gross_k) per public slot,
  withdrawal_hash,
  length,                             the element count, the count and the version included
  1 ]                                 TRANSFER_STATEMENT_VERSION
```

- The head is the audit head under `CRTX` in place of `CRAU`, the `layout` bits are `exits`,
  `key_escrow` and `full_openings` as below. `key_escrow` equals `mode == ConfidentialEscrow`.
- `in_proof` is the frame's `OWNER_IN_PROOF` flag, `delegate` is the `AuthorityTransfer` tag.
  `exempt` is the frame's `EXEMPT` flag, `approval_required` its `APPROVAL_REQUIRED` flag,
  refused on the authority rail.
- `output_chain`, `body_chain`, `recipient_key_chain` and `disclosure_chain` are the delivered
  and anonymous audit chains below.
- `sender` is `solana_owner_identity` of the sole owner signer under a policy, of the framed
  owner key on the in-proof rail, and zero on the signer rail off a policy and on the authority
  rail. The party identities are those of the anonymous audit.
- `policy_hash` is the ring account's written hash, zero on an audit-only ring. `own_root` and
  `curator_root` are the registry roots at the frame's revisions. `own_root` is zero when no
  registry is read, `curator_root` is zero without a curator.
- `recipient_o` is output `o`'s owner identity from the frame under a policy, zero off one and
  for a dummy slot.
- A public slot holds SPP's asset field, `right_align(net)` for a positive net or `q - |net|` for
  a negative one, and the gross withdrawal of the asset as `right_align` of a u128, deposits
  excluded. Slots past the used ones are zeros. Under `exempt` the circuit bounds every gross
  to u64 and to the asset's own-record `withdrawal_threshold`.
- `withdrawal_hash` is the policy withdrawal hash below. The count and the nonzero version close
  the chain, a statement of another length or layout hashes apart.

The head has 12 elements:

| # | Element | Source |
|---|---|---|
| 0 | `CRTX` | constant |
| 1 | `n0` | the frame's first nullifier, SPP nullifier `0` |
| 2 | `ring_id` | `hash_bytes` of the executing program id |
| 3, 4 | `pack_be(0x04 \|\| tx_viewing_u)` | frame, SPP `tx_viewing_pk` |
| 5, 6 | `pack_be(auditor_pubkey)` | ring policy |
| 7, 8 | `pack_be(0x04 \|\| eph_u)` | frame |
| 9 | `hash_bytes(sealed)` | frame |
| 10 | `right_align(salt)` | frame, SPP salt |
| 11 | `right_align(layout)` | exits from the outputs, the other bits from the frame, bit value `4` clear |

The chains over the published output slots:

- `output_chain = HashChain4(output hashes)`, every slot, a dummy included.
- `body_chain = HashChain4(body hash per slot)`, `hash_bytes(body)` of a delivered slot and `0` for an exit, confidential family only.
- `recipient_key_chain = HashChain4(pack_be(u) per slot)`, two zero fields for an exit, confidential family only.
- `disclosure_chain = HashChain4(disclosure)` over exactly the fields the layout publishes.
- `withdrawal_hash = HashChain4([CRPW, right_align(count), (owner, asset, right_align(amount)) per withdrawal leg])`,
  in settlement order under a policy and over no leg otherwise. A SOL leg's owner is
  `solana_owner_identity(recipient)`, an SPL leg's owner is the identity of the token account's
  owner.

No tag and no body of an anonymous slot enters the statement. The party identities are
`solana_owner_identity` of the payer, the signing co-signer and the withdrawal destination, each `0`
when absent. The circuit holds every spent UTXO to the sender on the in-proof and authority rails
and to the hidden owner on the anonymous rail, and reopens SPP's `private_tx_hash` over the same
inputs and outputs with no address input. `private_tx_blinding` stays private.

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

`spp_data` is the forwarded SPP data from its tag byte `18`. Slots past `count` are zero. `anonymous` is `mode == Anonymous`. `key_escrow` is `mode == ConfidentialEscrow`. `registry_root` is the own root at the prefix's `own_revision` in `ConfidentialEscrow` mode or on a policy ring, else `0`. `curator_root` is the curator root at the prefix's `curator_revision` when a policy source names a curator, else `0`. `policy_hash` is the registry's written policy hash on a policy ring, else `0`. `asset_i` is the SPP asset field of entry `i`'s group, `SOL_ASSET_FIELD` or `hash_bytes(mint)`, and `amount_i` its amount.

## Merge

```text
[ CRMG, private_tx_hash, output_utxo_hash, n0, ring_id,
  pack_be(auditor_pubkey), pack_be(eph_pk), hash_bytes(ciphertext), right_align(salt),
  HashChain4(disclosure fields),
  party_0, party_1, party_2, right_align(key_escrow), member_registry_root ]
```

The salt is the SPP merge output salt. The party identities are the payer, the signing co-signer and `0`. `key_escrow` is `mode == ConfidentialEscrow`, and then `member_registry_root` is the own root at the merge's `own_revision`, else `0`. SPP's merge proof binds the same `private_tx_hash` and nullifiers.
