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
2. **Privacy**

   **Purpose:**
   1. Protect users’ financial activity from public observers while allowing auditor access.
   
      **Technical requirements:**
   2. Hide private UTXO amounts, assets and blindings from public observers.
   3. **Confidential transfers:** Sender identities, recipient viewing keys and policy-required owner identities may be public.
   4. **Anonymous transfers:** Hide the anonymous sender’s identity and ring recipient identities. Explicit public co-owners, default-ring input owners and exit owners remain public.
   5. Public deposit and withdrawal amounts and assets, transaction structure and the grouping of outputs within a transaction may remain visible.
3. **Composability**

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
   2. Allowlist entries may be public or private. Private entries must not reveal members’ identities to public observers.
   3. Using the allowlist must not reveal the identities of the owners sending or receiving funds to public observers.
   
      **Cases:**
   
         Apply the configured sender and recipient allowlisting to each case, regardless of which instruction handles it.
   4. **Transfer within the ring:** Check spent UTXO owners and receiving UTXO owners.
   5. **Deposit:** Check receiving ring UTXO owners.
   6. **Withdrawal:** Check spent UTXO owners and public withdrawal recipients.
   7. **Entry from the default ring:** Check spent default-ring UTXO owners and receiving ring UTXO owners.
   8. **Exit to the default ring:** Check spent ring UTXO owners and receiving default-ring UTXO owners.
   9. **Merge:** No allowlist checks; ownership remains unchanged.
   10. **Delegate transfer:** No allowlist checks; authorization is covered by the permanent delegate policy.
5. **Owner blocklisting and freezing**

   **Purpose:**
   1. Prevent selected owners from sending or receiving funds.
   
      **Technical requirements:**
   2. Blocklist and freeze-list entries may be public or private. Private entries must not reveal members’ identities to public observers.
   3. Using the blocklist must not reveal the identities of the owners sending or receiving funds to public observers.
   4. Blocking and freezing can use separate lists.
   
      **Cases:**
   
         Apply the configured sender and recipient restrictions to each case.
   5. **Transfer within the ring:** Check spent UTXO owners and receiving UTXO owners.
   6. **Deposit:** Check receiving ring UTXO owners.
   7. **Withdrawal:** Check spent UTXO owners and public withdrawal recipients.
   8. **Entry from the default ring:** Check spent default-ring UTXO owners and receiving ring UTXO owners.
   9. **Exit to the default ring:** Check spent ring UTXO owners and receiving default-ring UTXO owners.
   10. **Merge:** No blocklist checks; ownership remains unchanged.
   11. **Delegate transfer:** No blocklist checks; authorization is covered by the permanent delegate policy.
6. **Asset allowlist**

   **Purpose:**
   1. Restrict assets entering, moving within or leaving the ring to approved assets.
   
      **Technical requirements:**
   2. Enforcing the asset allowlist must not reveal private UTXO assets to public observers.
   
      **Cases:**
   3. **Transfer within the ring:** Check assets of spent and receiving UTXOs.
   4. **Deposit:** Check deposited assets.
   5. **Withdrawal:** Check withdrawn assets.
   6. **Entry from the default ring:** Check assets entering the ring.
   7. **Exit to the default ring:** Check assets leaving the ring.
   8. **Merge:** No asset-allowlist checks; the asset remains unchanged.
   9. **Delegate transfer:** No asset-allowlist checks; authorization is covered by the permanent delegate policy.
7. **Amount guards**

   **Purpose:**
   1. Apply recipient or asset restrictions only when an amount exceeds a configured threshold.
   2. use case, part of the custom ring users are not kyced a part are kcyed
   
      **Technical requirements:**
   3. Evaluating the guard must not reveal private amounts or assets to public observers.
   
      **Cases:**
   
       Sum receipts per owner and asset for recipient rules, or per asset for asset rules, within the transaction.
   4. **Transfer within the ring:** Evaluate guards using transferred amounts.
   5. **Deposit:** Evaluate guards using deposited amounts.
   6. **Withdrawal:** Evaluate guards using withdrawn amounts.
   7. **Entry from the default ring:** Evaluate guards using amounts entering the ring.
   8. **Exit to the default ring:** Evaluate guards using amounts leaving the ring.
   9. **Merge:** No amount-guard checks.
   10. **Delegate transfer:** No amount-guard checks; authorization is covered by the permanent delegate policy.
8. **Per-transfer outflow caps**

   **Purpose:**
   1. Limit each owner’s net outflow per asset within one transaction.
   
      **Technical requirements:**
   2. Checking the cap must not reveal private amounts, assets or owner identities to public observers.
   
      **Cases:**
   
       Aggregate outflow per owner and asset across the transaction. Subtract funds returned to the same owner in ring UTXOs.
   3. **Transfer within the ring:** Count funds sent to other owners.
   4. **Deposit:** No outflow-cap checks; public funds enter the ring.
   5. **Withdrawal:** Count withdrawn funds toward the owner’s outflow.
   6. **Entry from the default ring:** Count funds sent to other owners; exclude funds received by the same owner within the ring.
   7. **Exit to the default ring:** Count exited funds, including exits to the same owner.
   8. **Merge:** No outflow-cap checks.
   9. **Delegate transfer:** No outflow-cap checks; authorization is covered by the permanent delegate policy.
9. **Co-signer approval thresholds**

   **Purpose:**
   1. Require additional approval when an owner’s outflow or public withdrawals exceed configured thresholds.
   
      **Technical requirements:**
   2. Checking thresholds must not reveal private amounts, assets or owner identities. Whether approval is required may be public.
   3. Require approval if any configured threshold is exceeded.
   
      **Cases:**
   
      Calculate owner outflow as defined by the outflow cap. Aggregate gross public withdrawals per asset across the transaction, without subtracting deposits.
   4. **Transfer within the ring:** Apply owner-outflow thresholds to funds sent to other owners.
   5. **Deposit:** No outflow or withdrawal threshold applies to a deposit alone.
   6. **Withdrawal:** Apply both owner-outflow and gross-withdrawal thresholds.
   7. **Entry from the default ring:** Apply owner-outflow thresholds to funds sent to other owners; exclude funds received by the same owner within the ring.
   8. **Exit to the default ring:** Apply owner-outflow thresholds, including exits to the same owner.
   9. **Merge:** No approval-threshold checks.
   10. **Delegate transfer:** No approval-threshold checks; authorization is covered by the permanent delegate policy.

10. **Permanent delegate**

    **Purpose:**

    1. Allow a configured delegate to move funds without owner authorization.

    **Technical requirements:**

    1. Require authorization from the delegate configured by the ring policy.
    2. Delegate transfers bypass the other transfer policies; auditor recovery remains required.

    **Cases:**

    1. **Transfer within the ring:** The delegate may move funds between owners without their signatures.
    2. **Deposit:** Delegate authority cannot authorize spending public funds.
    3. **Withdrawal:** Permitted with delegate authorization.
    4. **Entry from the default ring:** Delegate authority cannot spend default-ring UTXOs.
    5. **Exit to the default ring:** Permitted with delegate authorization.
    6. **Merge:** Normal merge authorization applies; no additional delegate-policy checks.
    7. **Delegate transfer:** Require the configured delegate’s authorization and apply auditor recovery, without the other transfer-policy checks.



&nbsp;

&nbsp;

&nbsp;

&nbsp;

**Notes:**

1. With input and output allowlisting, removal blocks sending and receiving; a separate freeze list only adds “receive but not spend.”
2. Should we add asset block list?
3. Should amount guards also add a min transfer?
4. Do we need Co-signer approval thresholds. at all or is a co signer policy in the relayer sufficient?
