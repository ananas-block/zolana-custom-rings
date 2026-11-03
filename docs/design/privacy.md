# Privacy by mode

The confidential modes and the anonymous mode differ at the sender and the recipients. Amounts, assets and blindings stay private from chain observers in both. [Spec](../spec.md)

## Confidential rings

- Chain observers see the sender, each recipient's viewing key and, on a policy ring, each output's owner identity.
- The in-proof rail publishes the sender's key in the transfer data in place of an owner signer. An authority transfer shows the delegate in place of the sender.
- They see each exit owner and each public leg's account, asset and amount.
- They do not see amounts, assets, blindings or which notes a transfer spends.
- Every payment to one recipient carries the same viewing key, and the zolana registry maps a registered viewing key to its owner. Payments to one recipient link to each other and name it.
- A deposit's view tag is the recipient's viewing key, which links the funder to the recipient.

## Anonymous rings

- Chain observers see the payer and the spent note count. They see the published output count and the change bits. They see a view tag and a body length on each recipient or dummy slot, and the sender bundle with its tag.
- A public co-owner signs in the open. Its link to the transfer is public, and the hidden owner's stays hidden.
- A reply has one length per frame, and a slot with no reply carries random bytes of that length. Observers see whether a frame carries reply bytes.
- They see each exit owner and each public leg. The auditor message length follows the published input count, the exits bitmap and the layout.
- They do not see the sender, the recipients, the amounts, the assets or the spent notes.
- The hiding holds only while all of these hold:
  1. The payer does not link to the owner.
  2. The transfer spends ring notes only. A default-ring spend publishes its owner.
  3. No exit or withdrawal pays a key linked to the owner.
  4. A first deposit takes a request tag. The bootstrap tag is the recipient's viewing key and links every bootstrap deposit to it.
  5. The wallet trusts its indexer, which pairs each spent leaf with its nullifier.
  6. The prover runs locally or in an attested enclave.
  7. The rules admit many owners. An allow rule bounds every sender and recipient to the public list.
  8. Deposit and withdrawal amounts and timing do not single out a later spend.
- A live recipient's tag derives from its slot secret, so it follows the first nullifier and the slot index. A dummy tag holds only a preimage, so a sender can repeat a live tag whose secret it knows, or encode data in it.
- Two outputs under equal view tags link to each other.

## Every mode

- Records are public. A record write names its member, and an escrow write names the owner's Solana key.
- An address enrollment publishes the owner, its nullifier key and its viewing key. A transfer's pool opening stays private, so it does not name which enrolled record it read.
- The rule table is public, so observers see which lists a ring screens and who is on them.
- A deposit publishes the funder, the asset and each amount.
- A merge links its input notes to one owner.

## Who else sees what

- The auditor decrypts each transfer output disclosure and deposit opening. It reads a spent note's hash or opening on every rail. With an escrowed nullifier secret it also links that owner's spends.
- Merge recovery needs known metadata for every real input. Naming the hidden sender on the anonymous commitment rail needs the first input's owner key.
- A reader sees what its grant covers, blindings included, and keeps it after a revocation.
- Ring RPC as relayer receives every secret the proofs need. It links the owner's spends and opens the outputs, so a relayed transfer is anonymous only toward a trusted Ring RPC.
- Ring RPC as co-signer sees each owner's debit of each asset. It reads them from the frame with the auditor key.
- The ring indexer sees which members a client opens, before the transfer lands.
- Photon sees which leaf each nullifier spends, and the deposit tags of one viewing key grouped per request. It sees which ring history a scanning wallet reads, and from which slot.
