A custom ring lets you enforce your own compliance rules on private transfers  
in the Solana Privacy Program: you define a policy that every transfer and  
withdrawal must prove it satisfies, and ring settings such as co-signer  
approval that your ring program checks directly. This document describes each  
control you can configure and who can change it.

1. Co-signer
2. Allowlist (kyc)
3. Blocklist (sanctions)
4. Curated lists (co-signer in ring rpc)
5. Frozen list
6. Asset allowlist
7. Sender limits (co-signer in ring rpc)
8. Token volume limits (co-signer in ring rpc)
9. Permanent delegate
10. Auditor
11. Readers
12. Pause
13. complex rules (max simplify) -

## Policy

A ring's policy is the set of rules that transfers and withdrawals through the  
ring must satisfy. The transaction proves it satisfies them without revealing  
amounts, recipients or which list entries it used.

### Policy and ring settings

- **Policy:** allowlist, blocklist, frozen list, asset allowlist and sender  
limits. The proof checks these, and only the  
upgrade authority can change them.
- **Ring settings:** co-signer, token volume limits, readers and pause. The  
ring program checks these, and the ring authority changes them.

### Rules and entries

- The policy fixes the rules: which lists are checked, for which party, and  
above which threshold.
- The ring authority adds and removes list entries without changing the  
policy.

## 1. Co-signer

A co-signer is a key that the ring authority designates to approve selected  
operations. The co-signer on its own cannot move funds.

### Operations that can require approval

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

### Configuration

- The ring config holds one co-signer.
- The co-signer can be a smart account to allow multiple approvers.
- The ring authority sets, replaces or removes the co-signer. It also selects  
the operations that need approval and the withdrawal thresholds per token.
- The transfer/withdrawal threshold is part of the policy, and only the  
upgrade authority can change it.

## 2. Allowlist

An allowlist is a list of approved identities that the ring authority  
maintains, and the ring can require parties to a transfer to be on it. List  
entries are public: anyone can see which identifiers are on the list and  
when entries were added or removed. A transfer proves its checks without revealing which  
entries it used.

### What can be checked

- **Sender:** the sender must be on the allowlist.
- **Recipients:** every recipient must be on the allowlist.
- **Recipients above a threshold:** a recipient must be on the allowlist only  
when it receives more than a threshold of a token in one transaction,  
summed across outputs. Thresholds are set per token, and a token without a  
threshold is refused.
- **Combined with other lists:** for example, on the allowlist and not frozen,  
or on the allowlist or on the approval list.

### Configuration

- The ring authority adds and removes entries.
- The list is the ring's own, or one shared by a curator ring.
- Sender and recipient checks are configured independently, each with its own  
list, and a transfer must pass all configured checks.
- Which checks apply is part of the policy, and only the upgrade authority can  
change it.

## 3. Blocklist

A blocklist is a list of identities or tokens the ring refuses transfers to  
or from. A block takes effect as soon as the entry is added. Block lists can be shared.  
Entries are public, and a transfer doesn't reveal which entries it checked.

### What can be checked

- **Sender:** the sender is not on the blocklist.
- **Recipients:** no recipient is on the blocklist.
- **Tokens:** no token moved is on the blocklist.
- **Approval list exception:** a blocked party passes if it is on the ring's  
approval list. A ring that uses a curator's shared blocklist can't remove  
entries from it, so the approval list lets it clear individual parties  
locally.

### Configuration

- The ring authority adds and removes entries on its own blocklist and  
approval list.
- The blocklist is the ring's own, or one shared by a curator ring, such as a  
sanctions list.

## 4. Curated lists

A curator is a ring that maintains lists other rings read, for example a  
compliance provider running a sanctions blocklist. A change the curator makes  
applies to every subscribing ring as soon as the entry is added.

### What can be shared

- **Any list a rule reads:** allowlist, blocklist, frozen list or approval  
list. The source is chosen per list, so a ring can read its blocklist from a  
curator and keep its own allowlist.
- **Local exceptions:** a subscribing ring can't change a curated list. It  
clears individual parties through its own approval list.

### Configuration

- Any ring can act as a curator, and no registration is needed.
- The ring authority points each list at its own entries or at a curator, and  
can switch later without changing the policy.
- A subscribing ring trusts every entry its curator adds or removes.

## 5. Frozen list

A frozen list holds identities whose funds the ring freezes. A frozen identity  
keeps its balance but can't send or withdraw until the ring authority removes  
the entry. A freeze takes effect as soon as the entry is added.

### What can be checked

- **Sender:** the sender is not on the frozen list. This is the usual use, and  
the `allowlist` example combines it with an allowlist: an approved sender is  
still refused while frozen.
- **Recipients or tokens:** the frozen list can be checked like any other  
list, though a blocklist usually covers those cases.

### Configuration

- The ring authority adds and removes entries.
- The list is the ring's own, or one shared by a curator ring.
- Which checks apply is part of the policy, and only the upgrade authority can  
change it.

## 6. Asset allowlist

An asset allowlist limits which tokens can move through the ring. A transfer  
or withdrawal of any other token is refused.

### What can be checked

- **Tokens:** every token moved must be on the asset allowlist.

### Configuration

- Approved tokens are entries on a configured allowlist, next to approved  
identities.

## 7. Sender limits

A sender limit caps how much of a token one sender can transfer or withdraw,  
without revealing the amount.

### What can be checked

- **Outflow:** the total a sender moves out over a window of slots.

### Configuration

- Limits are set per token.

## 8. Token volume limits

A token volume limit caps how much of a token the whole ring deposits or  
withdraws publicly within a window of slots. Transfers inside the ring don't  
count.

### What can be checked

- **Deposits:** the ring's total public deposits of a token in the current  
window.
- **Withdrawals:** the ring's total public withdrawals of a token in the  
current window.

### Configuration

- The ring authority sets, per token, the window length and a deposit cap  
and/or a withdrawal cap.
- A token without a limit is uncapped.

## 9. Permanent delegate

A permanent delegate is a key that can move any user's funds to another user  
within the custom ring.

### What the delegate can do

- **Move funds within the ring:** the delegate signs each move. Moves pass the  
policy's list checks and transfer-scoped co-signer approval. Sender limits  
don't apply.

### Key registration

- Setting a delegate requires every user of the ring to register their  
spending key, encrypted to the ring's auditor, once, before they receive  
funds.
- The auditor's key recovers a user's UTXOs, and the delegate's signature  
authorizes moving them.

### Configuration

- The upgrade authority sets the delegate once. It can't be replaced or  
removed, and registration stays required.
- The Solana Privacy Program's governance must enable delegate moves for the  
ring.

## 10. Auditor

The auditor holds the ring's viewing key and can read every transfer and  
withdrawal through the ring: tokens, amounts and recipients. The auditor  
can't move funds.

### What the auditor sees

- **Transfers and withdrawals:** each one encrypts its details to the auditor,  
and the ring program accepts it only with a proof that it did.
- **Deposits:** token and amount are public, and each deposit proves that its  
recipient is encrypted to the auditor.

### Configuration

- The auditor key is configured when the ring is created.

## 11. Readers

A reader can see what the auditor sees, without holding the auditor key. The  
ring RPC decrypts transactions for readers the ring authority has granted  
access.

### Who can be a reader

- **Solana keys:** a reader signs each request with their wallet.
- **Passkeys:** a reader signs each request with a passkey, for example a  
regulator using a browser.

### Configuration

- The ring authority grants and revokes read access. Each grant is a public  
record on Solana.
- The ring authority itself has no read access unless it grants itself one.

## 12. Pause

Pausing stops all activity in the ring until it's resumed: deposits,  
transfers, withdrawals, merges and delegate moves. Funds stay where they are.

### Configuration

- The ring authority pauses and resumes the ring at any time.
- The Solana Privacy Program enforces the pause.

## Glossary


| #   | Term                     | Type           | Definition                                                                                                                                                                              |
| --- | ------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Member record**        | Registry entry | A public entry in the member registry for an owner or asset, containing list memberships, key escrow information and asset limits used to prove that a transfer meets the ring's rules. |
| 2   | **Ring RPC**             | Service        | Our hosted service that indexes member records, generates proofs, pays fees, submits transactions and serves decrypted activity to authorized readers. |
| 3   | **Ring Program**         | Solana program | Enforces ring controls and verifies proofs before authorizing note movements.                                                                                                           |
| 4   | **Policy Store Program** | Solana program | Stores versioned registry roots and verifies policy proofs for applications.                                                                                                            |
| 5   | **Curator**              | Solana program | Supplies member lists from another registry for a ring's policy checks.                                                                                                                 |
| 6   | **Wallet**               | User           | Holds spending keys and authorizes transfers of its ring notes.                                                                                                                         |
| 7   | **Reader**               | User           | Uses granted read access to query decrypted ring activity through Ring RPC.                                                                                                             |
| 8   | **Config Authority**     | Authority      | Sets ring policies, member lists, readers, co-signer requirements, fees and pause controls.                                                                                             |
| 9   | **Upgrade Authority**    | Authority      | Deploys and upgrades the ring program and authorizes its initial configuration and delegate setup.                                                                                      |
| 10  | **Auditor**              | Authority      | Holds the auditor key and decrypts ring transfers, deposits, merges and escrowed keys.                                                                                                  |
| 11  | **Co-signer**            | Authority      | Signs operations when the ring's configured scope or approval rules require it.                                                                                                         |
| 12  | **Delegate**             | Authority      | Uses delegated authority to move members' notes within a ring with key escrow.                                                                                                          |


## Flows

1. Ring deployment and initialization (skip)
2. Member enrollment and key escrow
3. Member record updates
4. Deposit
5. Transfer (confidential and anonymous)
6. Exit to the default ring
7. Public withdrawal
8. Note merge
9. Delegate transfer
10. Wallet synchronization and recovery
11. Transaction auditing
12. Reader access grants and revocation
13. Policy and mint limit updates
14. Curator list integration
15. Ring administration and authority changes
16. Policy Store initialization, updates and verification

## 2. Member enrollment and key escrow

Enrollment depends on the ring's policy. Key escrow is required on key-escrow rings, optional on other confidential rings, and unavailable on anonymous rings.

1. **Wallet:** Authorizes its member-record updates and, when registering an escrow key, encrypts its nullifier secret to the **Auditor**.
2. **Ring RPC:**

   1. Coordinates required authority-list updates with the **Config Authority**.
   2. Generates a key-registration proof when registering an escrow key.
   3. Submits the authorized member updates and any key registration to the **Ring Program**, paying the required fees.
   4. When queued updates are eligible, generates an apply proof and submits the registry update.
   5. Indexes the applied member records and serves their updated proofs.

## 5. Transfer flow

A unified flow for confidential and anonymous transfers.  
The difference should only be in the policy circuit, the policy circuit should do the same the confidential default ring circuit does and check the tags as public inputs.

1. **Wallet:** Signs the transfer authorization and sends it with the proof inputs to **Ring RPC**.
2. **Ring RPC:**

   1. Reads the required member records.
   2. Generates the required proofs.
   3. Obtains the **Co-signer** signature when required.
   4. Pays fees and submits the transaction to Solana.



&nbsp;

## Questions:

1. Do we always need key escrow? Only if we use permanent delegate right? For auditor only we dont need it.
