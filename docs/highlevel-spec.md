A custom ring lets you enforce your own compliance rules on private transfers  
in the Solana Privacy Program: you define a policy that every transfer and  
withdrawal must prove it satisfies, and ring settings such as co-signer  
approval that your ring program checks directly. This document describes each  
control you can configure and who can change it.

## Compliance Rules

1. ZK Policy
   1. Allowlist (kyc)
   2. Blocklist (sanctions)
   3. Frozen list
   4. Asset allowlist
   5. Auditor
2. Global Program Config
   1. Pause
   2. Permanent delegate
3. Ring Rpc
   1. Readers
   2. Co-signer
      1. Sender limits
      2. Token volume limits

## 1. ZK Policy

The policy defines which checks a transfer must prove. The ring authority configures these rules and maintains the list entries.

### 1.1. Allowlist

An allowlist is a list of approved identities that the ring authority  
maintains. Sender and or recipient must be on allow list.  
Recipients above threshold must be on allow list.

### 1.2. Blocklist

A blocklist is a list of identities or tokens the ring refuses transfers to  
or from. This freezes all tokens the blocked identity holds.

### 1.3. Asset allowlist

Only allowed assets can be deposited.  
Only allowed assets can be transferred.

### 1.4. Auditor

The auditor holds the ring's viewing key and can read every transfer and  
withdrawal through the ring: tokens, amounts and recipients. The auditor  
can't move funds.

## 2. Global Program Config

### 2.1. Pause

Pausing stops all activity in the ring until it's resumed: deposits,  
transfers, withdrawals, merges and delegate moves. Funds stay where they are.

### 2.2. Permanent delegate

A permanent delegate is a key that can move any user's funds to another user  
within the custom ring.

#### What the delegate can do

- **Move funds within the ring:** the delegate signs each move. Moves pass the  
policy's list checks and transfer-scoped co-signer approval. Sender limits  
don't apply.

#### Key registration

- Setting a delegate requires every user of the ring to register their  
spending key, encrypted to the ring's auditor, once, before they receive  
funds.
- The auditor's key recovers a user's UTXOs, and the delegate's signature  
authorizes moving them.

#### Configuration

- The ring authority sets the delegate once. It can't be replaced or  
removed, and registration stays required.
- The Solana Privacy Program's governance must enable delegate moves for the  
ring.

## 3. Ring RPC

### 3.1. Readers

A reader can see what the auditor sees, without holding the auditor key. The  
ring RPC decrypts transactions for readers the ring authority has granted  
access.

### 3.2. Co-signer

A co-signer is a key that the ring authority designates to approve selected  
operations. The co-signer on its own cannot move funds.

#### Operations that can require approval

- **Deposits:** every deposit into the ring.
- **Transfers:** every transaction through the ring, including withdrawals,  
transfers with a deposit leg and delegate moves. Plain deposits are  
excluded.
- **Withdrawals:** withdrawals whose public amount per token in one  
transaction exceeds a threshold. A token without a threshold needs  
approval for any amount.
- **Transfer/withdrawal threshold:** transfers or withdrawals whose total per  
token in one transaction exceeds a threshold, configured per token.  
Deposits have no threshold.

#### Configuration

- The ring config holds one co-signer.
- The co-signer can be a smart account to allow multiple approvers.
- The ring authority sets, replaces or removes the co-signer. It also selects  
the operations that need approval and the withdrawal thresholds per token.
- The ring authority sets the transfer/withdrawal thresholds.

#### 3.2.1. Sender limits

A sender limit caps how much of a token one sender can transfer or withdraw,  
without revealing the amount.

##### What can be checked

- **Outflow:** the total a sender moves out over a window of slots.

##### Configuration

- Limits are set per token.

#### 3.2.2. Token volume limits

A token volume limit caps how much of a token the whole ring deposits or  
withdraws publicly within a window of slots. Transfers inside the ring don't  
count.

##### What can be checked

- **Deposits:** the ring's total public deposits of a token in the current  
window.
- **Withdrawals:** the ring's total public withdrawals of a token in the  
current window.

##### Configuration

- The ring authority sets, per token, the window length and a deposit cap  
and/or a withdrawal cap.
- A token without a limit is uncapped.

## Glossary


| #   | Term                     | Type           | Definition                                                                                                                                                                              |
| --- | ------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Member record**        | Registry entry | A public entry in the member registry for an owner or asset, containing list memberships, key escrow information and asset limits used to prove that a transfer meets the ring's rules. |
| 2   | **Ring RPC**             | Service        | Our hosted service that indexes member records, generates proofs, pays fees, submits transactions and serves decrypted activity to authorized readers.                                  |
| 3   | **Ring Program**         | Solana program | Enforces ring controls and verifies proofs before authorizing UTXO movements.                                                                                                           |
| 4   | **Policy Store Program** | Solana program | Stores versioned registry roots and verifies policy proofs for applications.                                                                                                            |
| 5   | **Curator**              | Solana program | Supplies member lists from another registry for a ring's policy checks.                                                                                                                 |
| 6   | **Wallet**               | User           | Holds spending keys and authorizes transfers of its ring UTXOs.                                                                                                                         |
| 7   | **Reader**               | User           | Uses granted read access to query decrypted ring activity through Ring RPC.                                                                                                             |
| 8   | **Config Authority**     | Authority      | Sets ring policies, member lists, readers, co-signer requirements, fees and pause controls.                                                                                             |
| 9   | **Upgrade Authority**    | Authority      | Upgrades the ring program and creates its initial configuration.                                                                                                                        |
| 10  | **Auditor**              | Authority      | Holds the auditor key and decrypts ring transfers, deposits, merges and escrowed keys.                                                                                                  |
| 11  | **Co-signer**            | Authority      | Signs operations when the ring's configured scope or approval rules require it.                                                                                                         |
| 12  | **Delegate**             | Authority      | Uses delegated authority to move members' UTXOs within a ring with key escrow.                                                                                                          |


## Flows

1. Ring deployment and initialization (skip)
2. Member enrollment and key escrow
3. Member record updates
4. Deposit
5. Transfer (confidential and anonymous)
6. User Merge
7. Managed Merge
8. Delegate transfer
9. Wallet synchronization and recovery
10. Transaction auditing
11. Reader access grants and revocation
12. Policy and mint limit updates
13. Curator list integration
14. Ring administration and authority changes
15. Policy Store initialization, updates and verification

## 2. Member enrollment and key escrow

Enrollment depends on the ring's policy. Key escrow is required on key-escrow rings, optional on other confidential rings, and unavailable on anonymous rings.

1. **Wallet:** Authorizes its member-record updates and, when registering an escrow key, encrypts its nullifier secret to the **Auditor**.
2. **Ring RPC:**
   1. Coordinates required authority-list updates with the **Config Authority**.
   2. Generates a key-registration proof when registering an escrow key.
   3. Submits the authorized member updates and any key registration to the **Ring Program**, paying the required fees.
   4. When queued updates are eligible, generates an apply proof and submits the registry update.
   5. Indexes the applied member records and serves their updated proofs.

## 3. Member record updates

The **Wallet** updates its own viewing and recovery settings. The **Config Authority** updates the ring's policy list entries.

1. **Wallet or Config Authority:** Signs the changes it is authorized to make and sends them to **Ring RPC**.
2. **Ring RPC:**
   1. Reads the current member records and pending updates.
   2. Queues wallet updates until they are eligible to apply; prepares authority updates for immediate application.
   3. Generates the required proof and submits the registry update to the **Ring Program**, paying fees.
   4. Indexes the updated member records and serves their proofs.

## 4. Deposit

A deposit moves SOL or tokens from a wallet's public balance into ring UTXOs. The token and amount are public.

Compared with a transfer, a deposit adds a round trip for the **Wallet** to sign the transaction that moves its SOL or SPL tokens.

1. **Wallet:**
   1. Chooses the token, amount and recipient.
   2. Prepares the deposit UTXOs and encrypts their details to the recipient and the **Auditor**.
   3. Sends the deposit request to **Ring RPC**.
2. **Ring RPC:**
   1. Checks that the ring is active, the asset is allowed and any required recipient key escrow is registered.
   2. Generates the required deposit proof.
   3. Builds the deposit transaction and returns it to the **Wallet** for signing.
3. **Wallet:** Signs the prepared transaction to authorize the SOL or SPL token transfer and returns it to **Ring RPC**.
4. **Ring RPC:**
   1. Co-signs.
   2. Pays fees and submits the deposit to the **Ring Program**.
   3. Indexes the confirmed deposit so the recipient's **Wallet** can find its new UTXOs.

## 5. Transfer flow

A unified flow for anonymous,  confidential transfers, and withdrawals.

**Variants:**

1. anonymous: default
2. confidential:  policy circuit checks sender and recipients as public inputs same as default ring.
3. transfer to default ring: some outputs of a transfer can be owned by the default ring program.
4. public withdrawal: spl tranfer to 1 or multiple spl accounts, optionally alongside other transfers
5. **Wallet:** Signs the transfer authorization and sends it with the proof inputs to **Ring RPC**.
6. **Ring RPC:**
   1. Reads the required member records.
   2. Generates the required proofs.
   3. Obtains the **Co-signer** signature when required.
   4. Pays fees and submits the transaction to Solana.

## 6. User Merge

A merge combines UTXOs of the same wallet, token and ring into one UTXO with their total value. 

1. **Wallet:** Selects the UTXOs, prepares the merged UTXO and sends the merge request with its proof inputs to **Ring RPC**.
2. **Ring RPC:**

    1. Checks that the UTXOs are unspent and belong to the same wallet, token and ring.
    2. Generates proofs that preserve the wallet, token and total value and let the **Auditor** read the merged UTXO.
    3. Obtains the **Co-signer** signature when required.
    4. Pays fees and submits the merge to the **Ring Program**.
    5. Indexes the result, marking the input UTXOs spent and adding the merged UTXO.

## 7. Managed Merge

Managed merge is initiated by **Ring RPC** on a ring with a permanent delegate and registered escrow keys. It combines one wallet's UTXOs of the same token and ring while preserving their total value. The user should be able to configure, how many utxos with what average amount. 

1. **Ring RPC:**

    1. Selects unspent UTXOs belonging to the same wallet, token and ring.
    2. Uses the wallet's escrowed nullifier key to prepare the merged UTXO and encrypt its details to the **Auditor**.
    3. Generates proofs that preserve the wallet, token, ring and total value.
    4. Obtains the **Delegate** signature and any required **Co-signer** signature.
    5. Pays fees and submits the merge to the **Ring Program**.
    6. Indexes the result, marking the input UTXOs spent and adding the merged UTXO.



&nbsp;

## Notes

1. The program's upgrade authority is responsible only for upgrading the program and creating its initial configuration. The ring authority manages policy rules, list entries and ongoing ring settings.
2. We should implement support for multiple co signers using smart accounts in a hot path is too expensive. We can just create a pda per co signer and check it in the program.
3. We need to test that we can make the ring rpc relayer flow work with third party zk programs.
4. The wallet should never fetch merkle proofs.



## Questions:

1. Do we always need key escrow? Only if we use permanent delegate right? For auditor only we dont need it.
2. 
