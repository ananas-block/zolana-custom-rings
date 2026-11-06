# Circuit checks

## General

1. **Public input hash:**
   ```text
         fields = [
             CRTX, first_nullifier, ring_id,
             txpk0, txpk1, aud0, aud1,
             envelope_digest, salt, layout,
             in_proof, hidden, delegate,
             approval_mask, approval_totals, signer_data_counts, no_spend,
             output_count, output_chain, record_chain, tail_chain,
             input_count, input_nullifier_chain, private_tx_hash, sender,
             party_0, party_1, party_2, party_3, party_4, party_5, party_6,
             signer_count, signer_chain,
             policy_hash, own_root, curator_root, tracking_root,
             asset_0, net_0, gross_0,
             asset_1, net_1, gross_1,
             asset_2, net_2, gross_2,
             withdrawal_hash, 49
         ]
   
         h[0] = fields[0]
         h[i] = Poseidon(h[i-1], fields[3*i-2], fields[3*i-1], fields[3*i])
                for i = 1..16
   
         public_input_hash = h[16]
   ```
2. **Private transaction hash:** Recompute `private_tx_hash` and check that it matches SPP.
3. **Authorization mode:**  at most one mode must be set. `sender` must be zero unless `in_proof` is set.
   1. **Signer:** Owners sign the Solana transaction on a confidential ring; all three flags are zero.
   2. **In-proof:** Owner signs inside the SPP proof; their identity remains public. `in_proof = 1`.
   3. **Hidden:** One owner signs inside the SPP proof; public co-owners may also sign. `hidden = 1`.
   4. **Public owners:** Owners sign the Solana transaction on an anonymous ring; all three flags are zero.
   5. **Delegate:** The configured permanent delegate signs without owner signatures. `delegate = 1`.
4. **Audit data layout:** Only the following bits are permitted. `entry` and `single_asset_payout` must match the selected circuit key.
   1. **`has_data`:** Include UTXO data hashes in the auditor stream. When clear, both data hashes must be zero.
   2. **`entry`:** Include details of default-ring inputs in the auditor stream.
   3. **`single_asset_payout`:** Store one shared mint for all outputs. Requires `has_data = 0`.
5. **Counts:** Each count must fit the selected circuit key.
   1. **Inputs:** `1 ≤ input_count ≤ input_capacity`.
   2. **Outputs:** `1 ≤ output_count ≤ output_capacity`.
   3. **Signers:** `0 ≤ signer_count ≤ signer_capacity`.
   4. **Withdrawals:** `0 ≤ withdrawal_count ≤ withdrawal_capacity`.
6. **Audit key binding:** Require a clamped transaction viewing secret and derive its matching public key. Use that secret with the configured canonical auditor key for X25519; reject an all-zero shared secret.
7. **Encryption binding:** Derive the AES key and nonce using the labelled, salted Poseidon KDF and constrain AES-256-CTR encryption. Bind transmitted ciphertext bytes to `envelope_digest`, `record_chain` and `tail_chain`.

## Inputs

1. **Duplicate SPP checks:**
   1. Domain.
   2. Ordering.
   3. Dummy fields.
   4. Compact input padding.
   5. Ring ID of ring-owned inputs.
   6. 64-bit amount range (default-ring entry inputs).
   7. Address-chain reconstruction.
2. **Registration:** For each spent ring UTXO with `nullifier_pk != Poseidon(0)`, prove membership of its owner’s tracking record and match its registered key to `nullifier_pk`.
3. **Authorization binding:** Match spent UTXO owners to the mode.
   1. **Signer / public owners:** Owners must be public signers.
   2. **In-proof:** Owners must be public signers or `sender`.
   3. **Hidden:** Owners must be public signers or the hidden owner; the hidden owner must not be a public signer.
   4. **Delegate:** No signer-membership check.
4. **Owner coverage:** Ensure tracking and policy checks cover the actual spent UTXO owners.
   1. **Non-delegate:** Each spent UTXO owner must appear exactly once in the owner rows.
   2. **Delegate:** Same check, except zero-secret inputs need no owner row.
5. **No-spend flag:** Set `no_spend = 1` exactly when there are no UTXO inputs. Address and dummy inputs do not count as spends.
6. **Auditor input map:** Distinguish spent UTXOs, address inputs and padding for the auditor.
   1. **All modes:** Encrypt the spent UTXO count and address bitmap, derived from the input domains.
   2. **Entry:** Also encrypt the default-ring input bitmap.
7. **Default-ring input data:** Default-ring inputs require an entry key.
   1. **Default-ring UTXOs:** Verifiably encrypt their owner, nullifier public key, amount, mint, blinding and both data hashes to the auditor.
   2. **Other inputs:** Their entry data must be zero.
   3. **Purpose:** allow the auditor to restore the input UTXO hash.
8. **Nullifier list binding:** Hash `input_count` and the ordered, zero-padded nullifier list into `input_nullifier_chain`. Require `first_nullifier = nullifiers[0]`.
9. **Signer list binding:** Match signer identities to the program’s `signer_chain`.
   1. **Non-empty:** Hash the ordered identities, with zeros beyond `signer_count`.
   2. **Empty:** Require `signer_chain = 0`.
   3. **Delegate:** Require `signer_count = 0`.
10. **Hidden-owner privacy:** In hidden mode:
    1. The first input must be a UTXO; its owner is the hidden owner.
    2. The hidden owner cannot spend zero-secret UTXOs.
    3. The hidden owner must differ from the payer, funders, co-signers and exit/withdrawal destination.
11. **Owner row ordering:** Keep outflow attribution deterministic.
    1. **Non-delegate:** Nonzero owner identities must be strictly ascending, with zero rows last.
    2. **Delegate:** No ordering check.

## Outputs

1. **Duplicate SPP checks:next**
   1. Output-blinding derivation; removable after the seed binding in Note 5.
   2. Output-chain binding for real outputs; see Note 9 for removal conditions.
   3. **Compact output padding:** Slots at or beyond `output_count` must not contain real UTXOs.
2. **Auditor output record:** Bind each encrypted record to its output’s UTXO fields.
   1. **Real outputs:** Kind, owner key, mint, amount and nullifier public key. The owner key and mint must hash to the committed owner identity and asset.
   2. **Dummies:** All-zero plaintext record (`kind = 0`), encrypted normally.
3. **Output registration:** Check each real ring output’s nullifier public key against its owner’s tracking record.
   1. **Nonzero-secret notes:** Require registration and a matching registered key.
   2. **Zero-secret notes (`Poseidon(0)`):** No registered-key match required; under private-list screening, prove the owner is unregistered.
   3. **Exits and dummies:** No registration check.
   4. **Literal zero:** Require `nullifier_pk != 0` for real ring outputs; zero-secret notes use `Poseidon(0)`.
4. **Output data hashes:** Bind the encrypted data records to the output commitments.
   1. **`has_data = 1`:** Verifiably encrypt each output’s `data_hash` and `ring_data_hash` to the auditor.
   2. **`has_data = 0`:** Require both hashes to be zero.
   3. **Dummies:** All-zero plaintext data record.
5. **Signer data counts:** Publish and constrain each public signer’s number of real outputs with nonzero `data_hash`, so they can verify they were shown every data-bearing output their signature authorizes.
6. **Single-asset payout:** In signer mode, require one ring input, one public signer and exactly 16 real ring outputs of the input’s asset. No default-ring entry, exits, public legs, withdrawals or data hashes.

## Public legs

1. **Withdrawal binding:** Match the withdrawal count and ordered recipient, asset and amount of each leg to the program’s `withdrawal_hash`, so policy checks cover the actual settlement.
2. **Withdrawal fields:**
   1. **Included legs:** Nonzero asset and `0 < amount < 2^64`.
   2. **Unused slots:** Recipient, asset and amount must all be zero.

## Policy checks

### Activation and table

1. **Policy activation:**
   1. **Rules:** Enforce when `policy_hash != 0`, except in delegate mode.
   2. **Caps and approval thresholds:** Enforce when `own_root != 0`, even without a rule table.
   3. **Delegate:** Bypass both; require `policy_hash`, `own_root` and `curator_root` to be zero.
2. **Policy binding:** When rules are active, hash the domain, nine list sources (list ID and registry), the salted list mask, the rule count and sixteen rule rows, and require the result to equal the program’s configured `policy_hash`.
3. **Policy decoding:** Require `0 <= policy_len <= 16` and activate only that prefix. Range-check rule fields, list masks and asset-limit fields, and require their decoded components to reconstruct the packed values. List masks are bounded to the nine source bits. The table decodes and hashes unconditionally; only the match to `policy_hash` is gated.
4. **List conditions:** A rule’s list condition passes if the subject belongs to at least one selected `present` list or is absent from at least one selected `absent` list. All applicable rules must pass. Stored tables are narrower: one polarity per rule, grant lists by presence, one deny list by absence; see 18.

### Records and lookups

5. **Policy records:** Authenticate each required owner or asset record under its configured ring or curator root.
   1. **Present:** Prove inclusion and use the committed record fields.
   2. **Absent:** Prove non-inclusion and use zero values.
   3. **Source:** A nonzero source registry selects the curator root. The circuit does not check which registry that root belongs to; see 18.
6. **Private-list lookup IDs:** Bind each owner’s private-list lookup ID to their registration. The salted mask selects which lists owners read at that ID; assets always read public records.
   1. **Registered:** The supplied salt must hash to the registered `list_tag`; derive the lookup ID from the owner identity and that salt.
   2. **Unregistered:** Prove absence from the tracking tree and treat private-list membership as absent. This holds only under the tracking floor; see 18.

### Rules

7. **Senders:** Require every owner row, and so every spent UTXO owner, to satisfy every active sender rule using authenticated list membership. Sender rules apply regardless of amount.
8. **Recipients:** Require every real output owner, including exits, and every public withdrawal recipient to satisfy each active owner rule, unless its amount guard exempts the corresponding payment total. Owner rules skip a zero owner identity.
9. **Assets:**
   1. **Outputs and withdrawals:** Require each asset to satisfy every active asset rule, unless its amount guard exempts the aggregate payment total for that asset.
   2. **Inputs:** Apply every unguarded asset rule to each spent UTXO’s asset, including zero-amount UTXOs.
10. **Guard totals:** Aggregate payments before applying amount thresholds.
    1. **Recipient:** Per owner and asset, `max(ring_outputs - ring_inputs, 0) + exits + withdrawals`.
    2. **Asset:** Sum these totals once per distinct owner.
    3. **Default-ring entry:** Default-ring inputs do not reduce the total; entry funding is a receipt.
11. **Guard thresholds:**
    1. **Always:** Enforce the list condition regardless of amount.
    2. **AboveAmount:** Exempt the rule when its guard total is at or below the rule’s fixed threshold.
    3. **AboveAmountByAsset:** Exempt a recipient rule when its guard total is at or below the threshold in the ring’s asset record. An asset without a record reads threshold zero, so the rule applies to any nonzero total.

### Outflow and approval

12. **Owner debit:** For each input owner and asset, compute `max(total_inputs - same_owner_ring_outputs, 0)`. Include default-ring inputs; exits and withdrawals do not count as returned funds.
13. **Charged outflow:** Add each owner’s share of exits and gross withdrawals not covered by total owner debits. Limit the extra charge to retained input value and split it proportionally to retained balances, using owner-row order for rounding. An exit a third party’s deposit funds still charges the owners who retained value.
14. **Outflow caps:** Require each owner’s charged outflow per asset to be at or below the cap in the ring’s asset record. A zero cap disables the limit; an asset without a record has no cap, no `cosign_above` and no withdrawal threshold.
15. **Approval mask:** Require `approval_mask` to equal the computed threshold results. It identifies the threshold-triggered co-signer approvals required: `0` means neither threshold triggered; `3` means both. The circuit proves the mask, and the program checks the required signatures.
    1. **Outflow (bit 0, value `1`):** Set when any owner’s charged outflow exceeds the asset’s nonzero `cosign_above`.
    2. **Withdrawal (bit 1, value `2`):** Set when an asset’s gross public withdrawals exceed its nonzero withdrawal threshold; deposits do not offset withdrawals.
16. **Approval totals:** When `approval_totals != 0`, require it to match a blinded hash of the assets, computed peak and total charged outflows, and gross withdrawals. Require zero when outflow checks are inactive.

### Shared

17. **Integer arithmetic:** Use bounded values to prevent field wraparound.
    1. **Comparisons:** Constrain the range-checked decomposition and comparison bit.
    2. **Division:** Require `numerator = quotient * divisor + remainder`, with `0 <= remainder < divisor`.
    3. **Maximum:** Require the result to be at least every candidate and equal to one.
18. **Program assumptions:** The circuit cannot see these; the program enforces them.
    1. **Live roots:** `own_root`, `curator_root` and `tracking_root` are current, and `curator_root` is the root of the registry the source map names.
    2. **Tracking floor:** `tracking_root` is at or above every salted source’s floor, else an owner a private list names could prove itself unregistered.
    3. **Legs:** `gross` is folded from the settled legs and `withdrawal_hash` from the legs’ accounts.
    4. **Table shape:** Write-time validation refuses what the circuit decodes freely: a guard on a sender rule, a per-asset guard off an owner rule, mixed polarity, more than one absent list, or a present list that is not a grant list.

## Verifiably encrypted ciphertexts

All three encrypt to the auditor using X25519, a Poseidon KDF and AES-256-CTR.

```text
Verifiably encrypted ciphertexts
|
+ Transfer auditor message - one AES stream
|  + Envelope
|  |  + Transaction viewing secret
|  |  + Spent UTXO count and address-input bitmap
|  |  + Entry only: default-ring input bitmap and input records
|  |  |  + Owner key, nullifier public key, amount, mint, blinding
|  |  |  + Data hash and ring data hash
|  |  + Single-asset payout only: shared mint
|  |
|  + Output record per included output slot
|  |  + Kind: ring output, exit or dummy
|  |  + Amount, owner key and nullifier public key
|  |  + Mint, except in single-asset payouts
|  |  + Dummies: all-zero plaintext
|  |
|  + Optional data record per output slot
|     + Data hash and ring data hash
|     + Dummies: all-zero plaintext
|
+ Merge auditor ciphertext
|  + New output's kind, amount, owner key, mint and nullifier public key
|  + Merge seed used to derive its blinding
|
+ Key registration auditor ciphertext
   + Owner's nullifier secret
   + Owner's private-list salt
```

Transfer output blindings are derived from the encrypted transaction viewing secret. Entry input records are zero for inputs that are not default-ring UTXOs.

## Renaming

1. `layout` → `audit_data_layout`: Flags selecting the auditor ciphertext format.
2. Enrolled / unenrolled → registered / unregistered: Whether the owner has a record in the tracking tree.
3. Private-list keys → private-list lookup IDs: Salted owner IDs used to locate private policy records.

## Notes

1. Why do we need **No-spend flag** ?
2. Default-ring input data, should be stored in a message.
3. We dont need to verifiably encrypt output blindings since we constraint the deterministically derived blindings.
4. Derive `private_tx_blinding` from the auditor-recoverable seed using SPP’s derivation. The shared `private_tx_hash` then lets SPP enforce output blindings, removing duplicate per-output checks from the ring circuit. No SPP changes required.
5. Pass precomputed `address_chain` as a private witness checked through `private_tx_hash`. If we remove the auditor address bitmap, we can also remove the full nullifier list and `input_nullifier_chain`; keep `first_nullifier`.
6. We should allow transfers from and to utxos with nullifier secret 0 and skip the registration requirement for those. We need to prove that there is no registered nullifier then.
7. Hidden-owner privacy restrictions are too strict: users should choose the privacy risks they accept. The SDK can provide safeguards instead of prohibiting those choices in the circuit.
8. `private_tx_hash` already binds real output fields and order. Consider removing `output_chain` after explicitly enforcing a real-output prefix and valid dummy suffix and applying the shared-seed binding in Note 5. Keep `output_count` to bind the number of output hashes and audit ciphertext records included in the instruction.
9. Proposed output layout: Store each output record in the corresponding UTXO’s output-slot data and verifiably encrypt it to the recipient’s viewing public key. The auditor can decrypt the same ciphertext using the transaction viewing secret recovered from the auditor envelope, provided the recipient’s viewing public key is available to the auditor.
10. Proposed output layout: Remove the separate optional data record per output slot. Data hashes need no encryption: they remain private witnesses bound by the UTXO hash, which the auditor can use directly for spend tracing.
11. The output-slot storage and recipient encryption proposed in Note 10 also apply to the merge auditor ciphertext.
12. Why do output owners need to be registered? This is probably unnecessary for spend tracing: input checks already require a matching escrowed key when spending. Private-list checks remain separate.
13. this is an interesting find **Signer data counts,** probably not necessary if the wallet just requires to see all outputs which makes sense
14. Note 9 likely makes the separate single-asset payout circuit unnecessary; sharing the mint can remain an optional encoding optimization.
15. The withdrawal `amount < 2^64` check is probably redundant: `withdrawal_hash` binds the amount to the program’s `u64` value. The nonzero checks are separate.
16. Consider unifying list lookups as `Poseidon(domain, owner_id, salt)`: use zero salt for public lists and the registered salt for private lists, selected by the policy. Both use the same hashing and membership logic; public entries require no registration.
17. Let's consider unifying the tree types. The tracking tree and the policy registries keep separate roots and revisions, so enrollment writes never race policy writes, but they could share one leaf layout and one pool gadget. A tracking leaf would be a registry record whose policy columns are zero, read under its own root. The circuit then opens every owner subject through one record pool with a per-subject root, and a sender's row and salted lookup read one view instead of two.
