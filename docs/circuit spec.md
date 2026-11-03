The ring circuits prove that deposits, transfers, merges and registry updates satisfy the ring’s applicable audit, policy and key escrow requirements.

## Circuits

The ring circuits have 11 families and 90 instantiations, each with its own proving key.


| Circuit family                    | Instantiations                                                                                                                 | Constraints                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          | Proving time (ms)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Delivered audit                   | 4:<br>`— → 2`<br>`— → 4`<br>`— → 8`<br>`— → 16`                                                                                | 103,182<br>162,641<br>281,902<br>518,961                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 260.8<br>407.7<br>637.6<br>1026.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Delivered audit with sender check | 4:<br>`48 → 2`<br>`24 → 4`<br>`16 → 8`<br>`8 → 16`                                                                             | 168,718<br>196,199<br>305,624<br>533,835                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 378.6<br>437.0<br>668.8<br>1188.3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Anonymous audit                   | 6:<br>`4 → 2`<br>`16 → 2`<br>`4 → 4`<br>`16 → 4`<br>`4 → 8`<br>`8 → 8`                                                         | 57,604<br>78,054<br>64,202<br>84,652<br>77,733<br>84,547                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             | 144.1<br>192.3<br>150.4<br>210.4<br>188.6<br>204.0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| Anonymous entry audit             | 3:<br>`8 → 2`<br>`8 → 4`<br>`8 → 8`                                                                                            | 72,152<br>78,750<br>92,281                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           | 180.3<br>194.1<br>212.0                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Member policy                     | 56: `— → 2`, `— → 4`, `— → 8`, `— → 16`;<br>each with 0, 1, 2, 4, 8, 16 or 32 withdrawals;<br>each with own or curator records | 2 outputs, own: 38,889, 43,280, 47,683, 56,518, 74,336, 107,708, 175,233<br>2 outputs, curator: 56,778, 67,690, 78,641, 97,297, 128,277, 185,241, 300,205<br>4 outputs, own: 56,869, 61,280, 65,703, 74,605, 91,268, 124,580, 192,384<br>4 outputs, curator: 87,826, 98,759, 109,702, 128,443, 156,834, 213,818, 329,049<br>8 outputs, own: 92,416, 96,546, 100,688, 108,960, 125,519, 159,105, 227,469<br>8 outputs, curator: 149,124, 159,051, 168,989, 186,012, 214,424, 271,744, 387,533<br>16 outputs, own: 160,536, 164,697, 168,868, 177,241, 194,108, 227,718, 296,265<br>16 outputs, curator: 263,885, 273,892, 283,910, 301,093, 329,813, 387,129, 501,564 | 2 outputs, own: 76.5, 83.5, 92.4, 108.4, 141.1, 173.3, 273.7<br>2 outputs, curator: 109.9, 128.1, 144.1, 172.3, 214.9, 298.9, 445.4<br>4 outputs, own: 105.4, 106.7, 129.9, 142.7, 163.9, 199.7, 309.0<br>4 outputs, curator: 161.9, 173.1, 190.0, 201.1, 284.2, 322.2, 478.1<br>8 outputs, own: 167.3, 172.1, 174.6, 175.9, 198.1, 260.2, 311.4<br>8 outputs, curator: 271.8, 268.2, 279.6, 311.2, 316.8, 439.5, 502.4<br>16 outputs, own: 269.1, 275.6, 292.0, 312.9, 303.3, 315.9, 434.3<br>16 outputs, curator: 448.5, 463.9, 452.4, 468.9, 480.1, 521.2, 583.2 |
| Delegate policy                   | 4:<br>`2 → 2`, own<br>`2 → 2`, curator<br>`4 → 4`, own<br>`4 → 4`, curator                                                     | 30,640<br>48,530<br>51,437<br>82,395                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | 59.5<br>98.9<br>101.5<br>154.4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Registry updates                  | 5: 1, 2, 4, 8 or 16 record writes;<br>no UTXO inputs or outputs                                                                | 16,339<br>31,727<br>62,469<br>123,794<br>246,444                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 33.7<br>65.5<br>114.1<br>219.3<br>381.3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Key escrow registration           | 1: one nullifier key;<br>no UTXO inputs or outputs                                                                             | 36,991                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | 109.3                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Deposits                          | 4: 1, 2, 4 or 8 deposited owner commitments;<br>no spent UTXO inputs                                                           | 68,333<br>90,435<br>134,668<br>223,256                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | 176.2<br>205.8<br>287.4<br>364.8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Merges                            | 2:<br>`8 → 1`<br>`24 → 1`                                                                                                      | 61,168<br>86,674                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     | 151.2<br>207.4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| Withdrawal exemptions             | 1: public withdrawal amounts and registry openings;<br>no UTXO inputs or outputs                                               | 12,318                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | 29.2                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| **Total**                         | **90**                                                                                                                         | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    | —                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |


Notes:

1. encryption circuits should be merged with the respective other circuits.

## Delivered audit

1. **Audit envelope:** Gives the auditor one transaction viewing secret, which unlocks every output and the disclosure.
2. **Recipient bodies:** Give each recipient its own amount and blinding. The auditor can open these same ciphertexts, so those values need no second encrypted copy.
3. **Audit disclosure:** Gives the auditor the additional information needed to identify and reconstruct outputs: owner keys, nullifier public keys and exit details. Poseidon masking keeps this compact and inexpensive to prove.

```rust
// Encrypted to the auditor using X25519 + AES-256-CTR.
struct AuditEnvelopePlaintext {
    tx_viewing_secret: [u8; 32],
}

// Encrypted to each recipient; the auditor can also decrypt it.
struct DeliveredBodyPlaintext {
    blinding: [u8; 32], // Big-endian field element.
    amount: u64,       // Encoded big-endian.
}

// Masked with a Poseidon pad derived from the transaction viewing secret.
struct DeliveredDisclosurePlaintext {
    output_blinding_seed: Option<Field>, // Present when there are exits.
    nullifier_keys: Option<Vec<Field>>,  // Omitted in key escrow mode.
    outputs: Vec<OutputDisclosure>,
}

enum OutputDisclosure {
    Ring { owner_key: [u8; 32] },
    Exit { asset: Field, amount: u64 },
    Dummy,
}
```

`Field` denotes a field element; these are logical layouts before packing and encryption.

## Anonymous audit

```text
Anonymous transaction
|
+ Public context
|  + Transaction viewing public key
|  + Salt
|
+ Output slots
|  + Output commitment
|  + View tag
|  + Recipient ciphertext - AES
|     + Verified fields: owner public key, mint, amount
|     + Unverified fields: sender viewing public key, blinding, data
|
+ Sender message
|  + Sender view tag
|  + Sender ciphertext - AES
|     + Verified fields
|     |  + Owner public key
|     |  + SPL mint and change amount
|     |  + SOL change amount
|     |  + Recipient viewing public keys
|     + Unverified fields
|        + Blinding seed
|        + SPL data
|        + SOL data
|
+ Auditor message - encryption checked by the proof
   + Auditor view tag
   + Ephemeral public key
   + Encrypted transaction viewing secret - AES
   + Encrypted disclosure - Poseidon
      + Output blinding seed, when there are exits
      + Output nullifier public keys
      + Each output's owner key, asset and amount
      + Spent inputs
         + Ring spend: first input hash and remaining hash prefixes
         + Entry: sender keys and each input's amount, asset and blinding
```

Change slots have no body; their details are in the sender ciphertext. Dummy slots contain random bytes. Exit slots use a confidential recipient body containing asset ID, amount, blinding, ring ID and data.

"Verified fields" preserves the SDK terminology; the anonymous audit proof does **not** check the recipient or sender ciphertexts.

### Anonymous Encryption sizes

Sizes assume one input, one change output, no exits and empty data.


| Output slots | Recipient/dummy slots | Sender + recipient ciphertexts | Auditor ciphertexts | Total encryption data |
| ------------ | ---------------------: | ------------------------------: | -------------------: | ---------------------: |
| 2            | 1                     | 290 B                          | 288 B               | **760 B**             |
| 4            | 3                     | 636 B                          | 512 B               | **1,398 B**           |
| 8            | 7                     | 1,328 B                        | 928 B               | **2,642 B**           |


Each recipient body is **140 B**. The sender body is **117 + 33 × R B**, where `R` includes recipients and dummies.

### Notes

1. The recipient learns the sender's viewing public key, but not its signing public key or full shielded address, so it cannot send a payment back using only the received payload. We could consider to add optional sender signing key and nullifier pubkeys to enc data, this way the boostrap flow will work and the sender remains private.
2. If note-level linkability is not required, we could remove the Poseidon-encrypted disclosure and instead encrypt the sender identity and verified output fields to the auditor, with the proof checking that they match the transaction. Spent-input hashes, prefixes and full input openings would be omitted.
3. The anonymous audit requires every real input to have the same owner, enforced by `spentBySender` in `prover/circuits/audit/anonymous.go`; the SDK also rejects mixed owners. This is too restrictive: anonymous transactions should support inputs from multiple owners, including PDA-owned UTXOs, as Zolana supports.
4. A separate Poseidon-encrypted disclosure uses more instruction data but fewer constraints. The measured simplified variant removes input linkability and proves the verified fields in the sender and recipient AES ciphertexts using the delivered audit's Poseidon KDF and Zolana's optimized X25519. If we make it mandatory to escrow nullifier keys we can trace everything even if we omit the encrypted disclosure.

   | Outputs | Current bytes | Simplified bytes | Saved bytes | Current constraints | Simplified constraints | Added constraints |
   | -------: | -------------: | ----------------: | -----------: | -------------------: | ----------------------: | -----------------: |
   | 2       | 760           | 632              | 128         | 57,604              | 119,715                | 62,111            |
   | 4       | 1,398         | 1,110            | 288         | 64,202              | 191,972                | 127,770           |
   | 8       | 2,642         | 2,066            | 576         | 77,733              | 336,725                | 258,992           |
   | 16      | 5,162         | 3,978            | 1,184       | 104,749             | 626,978                | 522,229           |

5. The SDK labels parts of the anonymous recipient and sender plaintexts as "verified fields", but their encryption is not currently checked by the proof. The anonymous audit proof verifies the separate auditor disclosure, not the recipient or sender ciphertexts.
6. Recipient-encryption guarantees differ between modes: delivered audit proves that each ring output's ciphertext encrypts the correct amount and blinding to its published viewing key, while anonymous audit proves the auditor disclosure and leaves recipient ciphertexts unchecked. This explains much of the constraint-count difference. We should use one consistent encryption scheme across the audit circuits, with the same proof guarantees for verified fields in both modes.
7. We should preserve SPP proof flexibility signer mix, compact and dummy padding etc
8. The auditor needs to be able to know when a UTXO is spent so that the ring rpc can only serve spendable UTXOs
9. We should skip the escrow nullifier key requirement if the nullifier key is zero to support shielded pdas and not require that those are registered.
10. There should be no separate confidential circuit instantiation the program should just pass a right side zeroed hash chain so that the public input is essentially free. Checks inside the circuit will also be cheap.

## Merge

**Notes:**

1. we can remove encrypted disclosure if we require nullifier key escrow. Then we can also simplify the circuit to really only verifiably encrypt the output cipher text, and potentially do policy checks. If we remove encrypted disclosure we can mirror the SPP proof input sizes.
2. Should we have policy checks at all in merge? You cannot send funds to anyone so...

## Policy

The policy rules are a `RuleTable`; a `SourceMap` selects the registry supplying each list.

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

// List entry
struct PolicySource {
    list_id: u8,         // Zero for an empty slot; otherwise 1 through 8.
    registry: [u8; 32],   // Registry field; zero selects the ring's own registry.
}
```

`policy_hash` commits to the domain, encoding version (currently 12), eight source slots, rule count and sixteen encoded rule rows. These are zero-padded to 44 field elements and folded with Poseidon. Unused encoded rule rows are zero. Per-asset thresholds and limits remain in `MemberRecord`.

### Lists

1. **Allow:** Authority-controlled approval of owners or assets for policies requiring allowlisting.
2. **Block:** Authority-controlled list of owners or assets that policy rules can exclude.
3. **Frozen:** Separate authority-controlled list used to stop selected owners from sending.
4. **Approval:** Additional authority-controlled approval list usable in policy rules and enrolment.
5. **Escrow:** Reserved list ID for nullifier-secret escrow; registration is recorded through `escrow_key`.

Allow, Block, Frozen and Approval affect transfers only when policy rules reference them.

### Non Policy Lists

1. **RingViewing:** Wallet-controlled flag with no current viewing behavior.
2. **Recovery:** Wallet-controlled flag with no current recovery behavior.
3. **Reader:** Grants access to decrypted activity through Ring RPC; current policy rules can also reference it.

**Notes:**

1. `Registry field; zero selects the ring's own registry.` consider to unify this to also check the hashed pubkey of the ring program. the ring program is just 1 of multiple whitelisted ones.
2. **RingViewing,** For viewing additional data is necessary, who, for how long or how many requests? (eg 1 time read) Whats the diff to Reader?
3. **Recovery,** What is recovery for?
4. **Reader,** why can it be referenced in the policy proof? Owner and authtority should be able to let people read

## Member policy

The membership-tree leaf is a `MemberRecord`:

```rust
struct MemberRecord {
    member: [u8; 32],     // Owner, asset or reader identity.
    next: [u8; 32],       // Next member in sorted order.
    lists: u64,          // Bits: 0=Allow, 1=Block, 2=Frozen, 3=RingViewing, 4=Recovery, 5=Reader, 6=Approval, 7=Escrow (reserved).
    escrow_key: [u8; 32], // EscrowKey hash, or zero before registration.
    mint_policy: MintPolicy,
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

The record is packed into nine field elements and hashed with Poseidon. For a wallet, `member` itself is the hash of its tagged owner public key.

 **Notes:**

1. if we move `escrow_key` into `MintPolicy` or just nest it so that we can easily check that a curated list has a zero as mint policy hash since it shouldn´t set the escrow key. Is there a case where we would try a curated list with the escrowed nullifier key? (maybe it makes sense if we have multiple custom rings that users dont need to escrow again for every custom ring. This would be a case to make this part of the registry program.)
2.
