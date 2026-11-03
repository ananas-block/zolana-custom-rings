# Audit and key escrow

The auditor holds one viewing key for the ring's life. That key opens every operation, and key escrow lets it link spends. [Spec](../spec.md)

## Transfers

- The sender draws a transaction viewing key for each transfer. The transfer proof shows its secret is sealed to the auditor in one auditor stream.
- The proof forces every published output blinding to derive from that secret, the salt and the first nullifier. The auditor rebuilds every published output.
- On the confidential and authority rails the proof also shows each delivered body opens for the viewing key the output publishes. The body holds the blinding, the amount, the owner key and the nullifier key. Under key escrow it omits the nullifier key.
- The recipient compares the decrypted keys with its own before it accepts the note. Under key escrow it compares the owner key and rebuilds the commitment with its own nullifier key.
- On the anonymous rail a record in the stream opens each output's owner, asset, amount and nullifier key. An exit's record opens its asset, its amount and, off key escrow, its nullifier key.
- The stream names each spent note by its full hash on every rail. An anonymous spend of default-ring notes opens every spent note.
- The program builds the ring statement from the frame it forwards to SPP, so the proof binds the transfer that settles. The policy and the withdrawal thresholds are sections of the same proof, switched by the policy hash and the exempt flag.

## Recipient delivery

- On the anonymous rail the proof binds each live ring output to its owner's address in the ring's own records. The body opens for the viewing key that address names.
- The proof binds the sender's address the same way and encrypts the sender bundle to it, so change rebuilds from the bundle. Every anonymous sender therefore enrolls, an entry sender and a sender with no change included.
- A slot is change exactly when its owner, nullifier key and viewing key equal the sender's address. A recipient at that exact address is change.
- A reply is optional and stays an unauthenticated claim. The wallet confirms it before it trusts the sender. A frame without a reply gives its recipients neither the sender's address nor a memo.
- The proof holds each tag to its form, see [Discovery](../spec/crypto/disclosure.md#discovery). A dummy tag holds a preimage and proves no sampling.

## Wallet scanning

- `AnonymousSync` reads the history of each ring the wallet's `ViewingHistory` names, then tests each slot and bundle tag for each held key.
- The key holder runs one agreement per candidate per key and returns a slot secret on a match. Raw agreements stay inside the holder.
- Deposits keep their tag streams, and merges keep their nullifier reads.
- `AnonymousSync::full_scan` reads a ring from its start, and tries every slot, bundle and deposit with no use of a tag.
- Only a final page's `context.slot` becomes a stored position. A failed page moves nothing, and a key added later is its own query.
- `AnonymousWallet` holds notes, pending notes, spends, reply claims and positions in one document. `absorb` takes a scan's results together, and the store replaces the document in one atomic write. A position is therefore never saved without what it covers.
- A note under a mint the registry does not name stays a pending note, with its verified opening. It is unspendable until `resolve_pending` admits it, and that read takes no history rescan.
- `RotatingRingKeys` holds one identity's current and retired viewing keys, so a note sealed to any of them opens.
- The CLI refuses a wallet store that holds no entry of the wallet's viewing key. It holds one current key per store, named by that key, and offers no rotation.

## Verified audit recovery

- Every published slot of a transfer whose proof verifies opens for the auditor.
- One ring disclosure ciphertext per slot is the guarantee, and the statement chains these ciphertexts.
- An exit's recipient body is a zolana ciphertext, and no ring proof binds it. A sender can settle an exit the auditor opens and its owner cannot.
- An evidence entry can name a note the auditor has not opened. An unnamed note leaves every output open on every rail.
- Under the anonymous commitment key an unnamed first note leaves the sender unnamed, because only that note binds the owner key. A later read with the note names the sender and opens the input.
- A delivered key escrow slot gives its proven owner key, amount and blinding before the auditor reads the owner's escrow record. An exit gives its asset and amount, its blinding from `seed_out`, and its owner from the owner key SPP publishes. The commitment is not rebuilt yet. The asset of a ring output stays unknown, because a delivered body omits it and only the nullifier key finds it.
- A note under the zero nullifier key rebuilds with no escrow record, so a reader tries the registered key and then the zero key.

## Deposits and merges

- A deposit seals each new note's owner hash, blinding and owner key to the auditor.
- On every ring the proof binds the sealed owner key to the owner identity the owner hash commits to, so the auditor names each owner.
- A merge seals a disclosure key to the auditor. The proof opens the ordered list of input hashes under it, zero at a dummy.
- The auditor marks every named input spent and records the output with the inputs' owner, asset and sum. That record is no wallet opening.
- An unnamed input leaves the merge unresolved, and each new opening resolves the merge and its descendants again.

## Key escrow

- A wallet escrows its nullifier secret by sealing it to the auditor with a proof of the seal. Ring RPC checks that proof before it writes the escrow entry.
- The record keeps a hash of the nullifier key and the sealed secret. The update publishes the owner key, the nullifier key and the sealed secret.
- A ring with a delegate requires an escrowed owner for every output, every deposit and every merge. A note under the zero nullifier key owes none, so a program-owned note needs no registration.
- An escrow key and an address in one record name one nullifier key. The accepted record update enforces this in either write order.
- With the secret the auditor computes that owner's nullifiers and links its spends. Ring RPC uses it for managed merges and delegate moves.
- An escrow key never changes. A write the storage authority signs directly can escrow a key the auditor cannot open.
- Ring RPC refuses a second escrow key, and the records circuit keeps a nonzero one. A secret sealed under an older schedule stays bound to its record, so a schedule change needs a fresh records registry or a fresh deployment.

## Why the audit stays provable

- A confidential policy ring publishes each output's owner identity beside its body, and only key escrow drops the nullifier key from that body.
- A frame publishes `m` slots and omits the rest of the key's capacity as a suffix. No index moves, and every chain cell past `m` reads zero. A key's proving cost does not fall with `m`.
- The payer, the co-signer, the registries and the notes spent decide whether a frame fits.
- A transfer statement without the recipient viewing key publishes less, and it loses the proof that each body opens for its recipient.
- The SDKs refuse a shape past the class as unkeyed, and the sender merges first. They refuse a keyed shape over the byte limit as too wide, and the sender splits the payout, publishes fewer slots or merges first.

## Reading through Ring RPC

- Ring RPC binds every audited row to the confirmed SPP event it rebuilds from the chain.
- Photon is trusted for completeness. A row Photon omits never reaches a reader.
- No nullifier secret leaves Ring RPC.
- `getUnspentUtxos` lists what the auditor opened and has not seen spent, beside the slots it covers. Each note reads only as not seen spent through `through_slot`.
- The read is a provisional observation at `confirmed` commitment. Photon has no rollback path, so an orphaned spend can hide a valid note and an orphaned output can appear available.
- A stale Photon row is not repaired by waiting until its slot is finalized.
- No authoritative balance, limit decision or debit reservation reads it.
- Merge selection reads the same spent mirror, so a stale spend can hide valid funds from merge selection. Ring RPC has no rollback detection and no reconciliation.
- `through_slot` is the backfill's last terminal page context. `complete` holds only while the latest pass reached a final page with nothing unresolved, and any failed or partial pass makes it false.
- A wallet-scoped read gets an incomplete-coverage indicator and no unrelated decrypted commitments. Detailed unresolved rows go only to a grant that authorizes them.
- Coverage starts past the newest historical row, so an older note is never reported as covered. A spend of an older note has an unnamed input, and `complete` stays false.

## Historical rows

- The program refuses the historical transfer and merge tags. Readers keep one decoding path for statement version 2, schemes 1 and 2, and prefix evidence.
- A prefix that fits several notes or none stays unresolved, and it never reads as covered.
- No version 3 frame decoder reads prefix evidence.
