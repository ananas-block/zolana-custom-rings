# Records and live roots

A ring's lists, escrow keys, addresses, mint settings and tree grants are records in a Storage program tree. [Spec](../spec.md)

## Records

- A record holds one member's list bits, its escrow key, its address hash and, for an asset, its mint settings.
- A member is an owner identity, a passkey reader, an asset, or the grant key of one wallet and one reader.
- Each record points to the next member in sort order. The records are the leaves of a 4-ary tree in insert order.
- A proof opens a present member by its leaf and an absent member by the record that brackets it. A prover cannot leave out the record that convicts its subject.
- A records tree has a fixed number of leaves, each member keeps its leaf permanently, and a full tree takes no new member.
- A curator serves list membership only. Mint settings, escrow keys and addresses always come from the ring's own records.
- Rules read the allow, block, frozen and approval lists only. No owner admits itself, and a reader grant moves no funds.
- The viewing flag a wallet writes is for off-chain use. List slot 5 stays reserved and unused, no writer and no rule reach it.
- Every write publishes its member and its values in instruction data, and the ring indexer serves each record with its path.

## Addresses

- An address is the nullifier key and the viewing key one owner signed, under the registry's ring id. The leaf holds its hash, and the ring indexer returns the preimage beside each opening.
- The hash covers the ring id, so a record of another ring does not open under this ring's statement.
- The authorization account keeps only the newest address. The nullifier key is fixed on one registry, and a later enrollment rotates the viewing key alone.
- One leaf holds one address, so one own registry serves one ring. `Initialize` and the records write refuse a registry whose ring id is another ring's. A wrong first nullifier key cannot be corrected on that registry.
- A nonzero address hash and a nonzero escrow key in one record name one nullifier key, see [the record writer](record-writer.md#address-writes).

## Root history

- A storage registry keeps its newest roots, each with a revision.
- A graced update keeps the outgoing root valid for the registry's grace period, so a proof in flight under it still lands.
- An immediate update retires every earlier root at once, and every proof under them fails.
- A graced update waits while the oldest kept root is still valid, so it never drops a valid root.

## Live roots

- The program reads each root live from the registry account the transaction passes, after it checks the account against the address the ring account binds.
- A proof names a root by its revision, and the program reads that root. The prover picks the revision, never the root.
- A direct sender that meets a retired root reads the newest root and proves again. Ring RPC never proves a relay again, so a relay that meets a retired root fails and the wallet sends a new request.

## How fast a change binds

- A graced write is in the newest root at once. A new proof can still name the old root for the grace period.
- Ring RPC checks reader grants against the newest root, so a graced grant revocation stops reads once its batch lands.

## Why live roots

- The program reads every root from the registry account, so no copy can lag a revocation. A graced update leaves the old root usable for the grace period.
- A forged root needs a forged registry.
- An operation that reads a root passes one or two registry accounts beside the ring account.
