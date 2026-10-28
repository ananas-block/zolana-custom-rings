## Glossary


| #   | Term                     | Type           | Definition                                                                                                                                                                              |
| --- | ------------------------ | -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Member record**        | Registry entry | A public entry in the member registry for an owner or asset, containing list memberships, key escrow information and asset limits used to prove that a transfer meets the ring's rules. |
| 2   | **Ring RPC**             | Service        | Coordinates proofs, pays fees and submits transactions as the relayer, and decrypts ring activity for authorized readers.                                                               |
| 3   | **Ring Indexer**         | Service        | Indexes member registries and serves their records and Merkle paths to clients.                                                                                                         |
| 4   | **Ring Prover**          | Service        | Generates zero-knowledge proofs for ring operations from client inputs.                                                                                                                 |
| 5   | **Ring Program**         | Solana program | Enforces ring controls and verifies proofs before authorizing note movements.                                                                                                           |
| 6   | **Policy Store Program** | Solana program | Stores versioned registry roots and verifies policy proofs for applications.                                                                                                            |
| 7   | **Curator**              | Solana program | Supplies member lists from another registry for a ring's policy checks.                                                                                                                 |
| 8   | **Wallet**               | User           | Holds spending keys and authorizes transfers of its ring notes.                                                                                                                         |
| 9   | **Reader**               | User           | Uses granted read access to query decrypted ring activity through Ring RPC.                                                                                                             |
| 10  | **Config Authority**     | Authority      | Sets ring policies, member lists, readers, co-signer requirements, fees and pause controls.                                                                                             |
| 11  | **Upgrade Authority**    | Authority      | Deploys and upgrades the ring program and authorizes its initial configuration and delegate setup.                                                                                      |
| 12  | **Auditor**              | Authority      | Holds the auditor key and decrypts ring transfers, deposits, merges and escrowed keys.                                                                                                  |
| 13  | **Co-signer**            | Authority      | Signs operations when the ring's configured scope or approval rules require it.                                                                                                         |
| 14  | **Delegate**             | Authority      | Uses delegated authority to move members' notes within a ring with key escrow.                                                                                                          |


## Flows

1. Ring deployment and initialization (skip)
2. Member enrollment and key escrow
3. Member record updates
4. Deposit
5. Transfer
6. Anonymous transfer
7. Exit to the default ring
8. Public withdrawal
9. Note merge
10. Delegate transfer
11. Wallet synchronization and recovery
12. Transaction auditing
13. Reader access grants and revocation
14. Policy and mint limit updates
15. Curator list integration
16. Ring administration and authority changes
17. Policy Store initialization, updates and verification

## Transfer flow

A unified flow for confidential and anonymous transfers.  
The difference should only be in the policy circuit, the policy circuit should do the same the confidential default ring circuit does and check the tags as public inputs.


1. **Wallet:** Signs the transfer authorization and sends it with the proof inputs to **Ring RPC**.
2. **Ring RPC:**
   1. Retrieves required member records from the **Ring Indexer**.
   2. Requests proofs from the **Ring Prover**.
   3. Obtains the **Co-signer** signature when required.
   4. Pays fees and submits the transaction to Solana.