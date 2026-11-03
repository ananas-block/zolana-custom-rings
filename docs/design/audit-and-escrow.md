# Audit and key escrow

The auditor holds one viewing key for the ring's life. That key opens every operation, and key escrow lets it link spends. [Spec](../spec.md)

## Transfers

- The sender draws a transaction viewing key for each transfer. The transfer proof shows its secret is sealed to the auditor in one auditor stream.
- The proof forces every output blinding to derive from that secret, the salt and the first nullifier. The auditor rebuilds every output.
- On the confidential and authority rails the proof also shows each delivered body opens for the viewing key the output publishes. The body holds the blinding, the amount, the owner key and the nullifier key. Under key escrow it omits the nullifier key.
- The recipient compares the decrypted keys with its own before it accepts the note. Under key escrow it compares the owner key and rebuilds the commitment with its own nullifier key.
- On the anonymous rail a record in the stream opens each output's owner, asset, amount and nullifier key. An exit's record opens its asset, its amount and, off key escrow, its nullifier key.
- The stream names each spent note by its hash or a prefix on the anonymous rail, and by a prefix on the in-proof and authority rails. An anonymous spend of default-ring notes opens every spent note.
- The program builds the ring statement from the frame it forwards to SPP, so the proof binds the transfer that settles. The policy and the withdrawal thresholds are sections of the same proof, switched by the policy hash and the exempt flag.

## Verified audit recovery

- Every slot of a transfer whose proof verifies opens for the auditor.
- One ring disclosure ciphertext per slot is the guarantee, and the statement chains these ciphertexts.
- Anonymous recipient and sender ciphertexts and exit recipient bodies are zolana ciphertexts, and no ring proof binds them. A sender can settle an output the auditor opens and its recipient cannot.
- The signer rail discloses no spent note.
- Tracing by prefix can stay ambiguous or unseen. Several ring notes can carry one prefix, and the auditor can lack the note a prefix or a full hash names.
- An unseen note leaves every output open on every rail. A transfer read before its note marks the input with its hash or prefix.
- Under the anonymous commitment key an unseen first note leaves the sender unnamed, because only that note binds the owner key. A later read with the note names the sender and opens the input.
- A key escrow slot gives its proven owner key, amount and blinding before the auditor reads the owner's escrow record, and the asset of an exit. Its commitment is not rebuilt, and the asset of a ring output stays unknown, because a delivered body omits the asset and only the nullifier key finds it.
- Ring RPC derives a note's nullifier from a secret nullifier key to decide that the note is spendable. It decides this only for an owner whose key it holds.

## Deposits and merges

- A deposit seals each new note's owner hash, blinding and owner key to the auditor.
- On every ring the proof binds the sealed owner key to the owner identity the owner hash commits to, so the auditor names each owner.
- A merge seals a disclosure key to the auditor. The proof opens the owner, the mint, the total, the output blinding and each input's hash under it.

## Key escrow

- A wallet escrows its nullifier secret by sealing it to the auditor with a proof of the seal. Ring RPC checks that proof before it writes the escrow entry.
- The record keeps a hash of the nullifier key and the sealed secret. The update publishes the owner key, the nullifier key and the sealed secret.
- A ring with a delegate requires an escrowed owner for every output, every deposit and every merge.
- With the secret the auditor computes that owner's nullifiers and links its spends. Ring RPC uses it for managed merges and delegate moves.
- An escrow key never changes. A write the storage authority signs directly can escrow a key the auditor cannot open.
- Ring RPC refuses a second escrow key, and the records circuit keeps a nonzero one. A secret sealed under an older schedule stays bound to its record, so a schedule change needs a fresh records registry or a fresh deployment.

## Why the audit stays provable

- A 16-output confidential policy payout sits at the byte ceiling, the payer, the co-signer and the registries the transaction names decide whether it fits.
- Fitting a wider one needs SPP to publish less per output, or a transfer statement without the recipient viewing key. The second loses the proof that each body opens for its recipient.
- A confidential key's input class is the widest shape that fits one transaction on the signer and in-proof rails without a policy. The envelope names each spent note on the in-proof rail, so its inputs set that limit.
- The SDKs refuse a shape past the class as unkeyed, and the sender merges first. They refuse a keyed shape over the byte limit as too wide, and the sender splits the payout or merges first.

## Reading through Ring RPC

- Ring RPC binds every audited row to the confirmed SPP event it rebuilds from the chain.
- Photon is trusted for completeness. A row Photon omits never reaches a reader.
- No nullifier secret leaves Ring RPC.
