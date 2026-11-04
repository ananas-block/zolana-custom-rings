1. **Auditor recovery**

   **Purpose:**
   1. Let the auditor monitor ring transactions.
   2. Let Ring RPC serve decrypted balances and history to authorized users.
   
      **Technical requirements:**
   3. Verifiably encrypt each UTXO’s owner, asset, amount and blinding to the auditor.
   4. **Linkability:** Let the auditor associate published nullifiers with spent UTXOs while hiding these spend links from public observers.
   5. **Cases:**
      1. **Transfer:** can be combined with other cases with the same flexibility as SPP circuit, auditor can recover amount, asset, owner, blinding of every real output utxo and link inputs
      2. **Entry from the default ring:** Recover inputs created outside the auditor’s scope.
      3. **Exit to the default ring:** Recover the created default-ring UTXO. Must be in the same layout as standard confidential transfers.
      4. **Withdrawal:** No additional encrypted information required.
      5. **Deposit:** Same as transfer.
      6. **Merge:** Same as transfer.
      7. **Delegate transfer:** Same as transfer.
      8. **Compact padding:** must be supported same as SPP circuit.
      9. **Dummies:** Indistinguishable from real outputs through public information. The auditor can reliably identify and skip them.

1. **Privacy**

   **Purpose:**
   1. Protect users’ financial activity from public observers while allowing auditor access.
   
      **Technical requirements:**
   2. Hide private UTXO amounts, assets and blindings from public observers.
   3. **Confidential transfers:** Sender identities, recipient viewing keys and policy-required owner identities may be public.
   4. **Anonymous transfers:** Hide the anonymous sender’s identity and ring recipient identities. Explicit public co-owners, default-ring input owners and exit owners remain public.
   5. Public deposit and withdrawal amounts and assets, transaction structure and the grouping of outputs within a transaction may remain visible.
2. **Composability**

   **Purpose:**
   1. Let applications build custom-ring transactions with the same transaction flexibility as SPP.
   
      **Technical requirements:**
   2. Support program-owned UTXOs and CPI flows.
   3. Preserve SPP’s supported owner combinations and signing methods.
   4. Preserve SPP’s supported input/output sizes and compact and dummy padding.

4. **Owner allowlisting**

   **Purpose:**

   1. Restrict sending or receiving funds to approved owners.

   **Technical requirements:**

   1. Do not reveal allowlist members’ identities to public observers.
   2. Using the allowlist must not reveal the identities of the owners sending or receiving funds to public observers.

   **Cases:**

   Apply the configured sender and recipient allowlisting to each case, regardless of which instruction handles it.

   1. **Transfer within the ring:** Check spent UTXO owners and receiving UTXO owners.
   2. **Deposit:** Check receiving ring UTXO owners.
   3. **Withdrawal:** Check spent UTXO owners and public withdrawal recipients.
   4. **Entry from the default ring:** Check spent default-ring UTXO owners and receiving ring UTXO owners.
   5. **Exit to the default ring:** Check spent ring UTXO owners and receiving default-ring UTXO owners.
   6. **Merge:** No allowlist checks; ownership remains unchanged.
   7. **Delegate transfer:** No allowlist checks; authorization is covered by the permanent delegate policy.



&nbsp;

&nbsp;

&nbsp;

&nbsp;

**Policy backlog:**

Define purpose, technical requirements and instruction cases for each policy.

1. Owner allowlisting.
2. Owner blocklisting and freezing.
3. Asset restrictions.
4. Amount guards.
5. Per-transfer outflow caps.
6. Co-signer approval thresholds.
7. Withdrawal exemptions.
8. Permanent delegate
