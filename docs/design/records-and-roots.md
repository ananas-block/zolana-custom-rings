# Records and live roots

A ring reads two kinds of tree, each in a Storage program account with its own root and its own write path. A policy registry contains lists, mint settings and reader grants. A tracking registry contains enrollments. [Spec](../spec.md)

## Why two trees

- A storage update names a revision, and a proof made against another revision fails. One tree would make enrollment and revocation race on that revision.
- `ApplyEnrollments` touches only the tracking root, and an authority write touches only a policy root. Enrollment traffic therefore cannot fail or delay a restrictive update.
- An authority cannot gate enrollment. Policy admission stays a separate list write.

## Records

- A policy record contains one member's list bits and, for an asset, its mint settings.
- A member is an owner identity, an owner's salted key, a reader key or an asset. It can also be the grant key of one wallet and one reader.
- Each record points to the next member in sort order. The records are the leaves of a 4-ary tree in insert order.
- A proof opens a present member by its leaf and an absent member by the record that brackets it. A prover cannot leave out the record that convicts its subject.
- A tree has a fixed number of leaves, each member keeps its leaf permanently, and a full tree takes no new member.
- Every write publishes its member and its values in instruction data, and the ring indexer serves each record with its path.

## Lists and rules

- A rule reads a list by presence or by absence. The grant lists are read by presence and the deny lists by absence.
- Presence on any grant list a rule names satisfies that rule. Absence from a deny list satisfies its rule, and rules join with AND.
- Each denial is a separate rule. The program refuses a row that reads several lists by absence, inverts a list's polarity or mixes presence with absence.
- An accepted policy can still restrict nothing.
- No rule reads the reader list or the wallet-written `ring-viewing` list. An owner therefore admits itself to nothing, and a reader grant moves no funds.
- A curator serves list bits only. Mint settings always come from the ring's own records.

## Private lists

- `PrivateAllow` and `PrivateBlock` are always salted. A private entry is an ordinary record under `Poseidon(CRPL, owner, list_salt)`, written through the same apply path.
- The tracking leaf contains `list_tag = Poseidon(CRPT, list_salt)`, proven at enrollment and final.
- While a subject has a tracking row, the circuit forces its salt to open that tag, so it forces the key too. A proven absent row is the one skip.
- A subject with no row reads no salted list. A deny rule on a salted list passes, and an allow rule on one fails.
- To list an unenrolled identity, a curator uses a public list keyed by owner. Later enrollment leaves that entry in force.
- A public and a private block are two rules. One rule over both would admit a publicly blocked owner with no private entry.
- The wallet derives its salt per ring from its viewing key, so an auditor that holds the nullifier secret cannot derive another ring's salt.
- Private lists serve one ring. A source of a salted list must pin the ring's tracking registry, so a curator that serves several rings keeps one registry per ring.
- A list writer reads an enrolled owner's salt through `getListSalt`, which checks the salt against the row's tag and never returns the nullifier secret.

## Tracking

- A tracking leaf contains one owner's nullifier key, ciphertext hash, viewing key, revision and list tag.
- `Enroll` needs the owner's signature, and a program signs its PDA through CPI. Any payer may fund it, and Ring RPC can relay it for a wallet with no SOL.
- A first enrollment carries a proof. It shows the ciphertext seals the secret of that nullifier key and the salt of that tag to the auditor key.
- The program supplies the ring id, the member and the auditor key from the signer and the registry. A proof for another ring, member or auditor fails.
- The program verifies that proof in the same instruction, and refuses the zero nullifier key.
- A later `Enroll` carries no proof and moves only the viewing key and the revision. The nullifier key, the list tag and the ciphertext are final.
- `ApplyEnrollments` is permissionless. An applier names the authorization accounts in any order, and the program computes each entry from the account, so no applier can alter one.
- An enrollment is complete only when its leaf sits under an accepted tracking root. A pending account grants nothing, because every check reads the root.
- A full tree refuses a new enrollment, and rotations of enrolled owners still apply.
- A ring creates its tracking registry at `Initialize` and pins its address. A forged registry with a matching ring id fails that address check.

## Root history

- A registry keeps its newest roots, each with a revision.
- A graced update keeps the outgoing root valid for the grace period, so a proof in flight under it still lands.
- An immediate update retires every earlier root at once, and every proof under them fails.
- A graced update waits while the oldest kept root is still valid, so it never drops a valid root.
- The program classifies each policy write from its masks. A write that touches a list a rule can read or mint settings is immediate, and any other write is graced.
- Every such list write therefore fails proofs in flight at that root, an allowlist addition included. Those proofs prove again.
- A tracking update is always graced, under a program constant. Many rotations wait on a full history and evict no root a proof in flight reads.

## Tracking floor

- An immediate write on a private source records the pinned tracking registry's newest revision as `tracking_floor`.
- The program refuses a frame that reads a salted list through that source and names a lower tracking root. Otherwise a blocked enrolled owner could prove itself unenrolled under an old root.
- The floor is the one exception to tracking grace.

## Live roots

- The program checks each registry account against the address the ring account binds, then reads its root live.
- A proof names a root by its revision, and the program reads that root. The prover picks the revision, never the root.
- A direct sender that meets a retired root reads the newest root and proves again. Ring RPC never proves a relay again, so a relay that meets a retired root fails and the wallet sends a new request.
- A delegate transfer and a merge read no policy root, so a policy update cannot fail them. Every transfer and deposit reads the tracking root.
- An audit-only ring with no records reads the tracking root alone.

## How fast a change binds

- A graced write is in the newest root at once. A new proof can still name the old root for the grace period.
- Ring RPC checks reader grants against the newest root, so a graced grant revocation stops reads once its batch lands.
- A curator's immediate write stops a subscriber ring at once, since the ring reads the curator's roots at transaction time.
