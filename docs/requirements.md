1. **Auditor recovery**

   **Purpose:**
   1. Let the auditor monitor ring transactions.
   2. Let Ring RPC serve decrypted balances and history to authorized users.
   
      **Technical requirements:**
   3. Verifiably encrypt each UTXO’s owner, asset, amount and blinding to the auditor.
   4. **Linkability:** Let the auditor associate published nullifiers with spent UTXOs while hiding these spend links from public observers.
   5. **Instructions:** Deposit, Transfer, Delegate transfer and Merge.
2. **Policy enforcement**

   **Purpose:**
   1. Let each ring control who can send or receive funds, which assets can be transferred, and under what conditions.
   
      **Technical requirements:**
   2. **Deposit:** Prove that receiving UTXO owners and deposited assets satisfy the configured policy rules.
   3. **Transfer:** Prove that real input owners, output owners and assets satisfy the configured policy rules, including exits and withdrawals.
   4. **Delegate transfer:** Check that permanent delegate is configured by the policy, correct authority signs, no checks beyond that.
   5. **Merge:** No transfer-policy checks, since owner and asset remain unchanged and no value moves between parties.

3. **Privacy**

   **Purpose:**

   1. Protect users’ financial activity from public observers while allowing auditor access.

   **Technical requirements:**

   1. Hide private UTXO amounts, assets and blindings from public observers.
   2. **Confidential transfers:** Sender identities, recipient viewing keys and policy-required owner identities may be public.
   3. **Anonymous transfers:** Hide the anonymous sender’s identity and ring recipient identities. Explicit public co-owners, default-ring input owners and exit owners remain public.
   4. Public deposit and withdrawal amounts and assets, transaction structure and the grouping of outputs within a transaction may remain visible.

4. **Composability**

   **Purpose:**

   1. Let applications build custom-ring transactions with the same transaction flexibility as SPP.

   **Technical requirements:**

   1. Support program-owned UTXOs and CPI flows.
   2. Preserve SPP’s supported owner combinations and signing methods.
   3. Preserve SPP’s supported input/output sizes and compact and dummy padding.



&nbsp;

&nbsp;