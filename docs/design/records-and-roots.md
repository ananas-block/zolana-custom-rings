# Records and live roots

A ring reads two kinds of state, each with its own root and its own write path. A policy registry in a Storage program account contains lists, mint settings and reader grants. SPP state trees contain the audit credentials, one per enrolled owner, and SPP tree 0 contains their addresses. [Spec](../spec.md)

## Why credentials sit apart from policy

- A storage update names a revision, and a proof made against another revision fails. One tree would make enrollment and revocation race on that revision.
- `Enroll` writes only SPP state, and an authority write touches only a policy root. Enrollment traffic therefore cannot fail or delay a restrictive update.
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
- The credential contains `list_tag = Poseidon(CRPT, list_salt)`, proven at enrollment and final.
- While a subject opens its credential, the circuit forces its salt to open that tag, so it forces the key too. A proven absent credential is the one skip.
- A subject proven absent reads no salted list. A deny rule on a salted list passes, and an allow rule on one fails.
- To list an unenrolled identity, a curator uses a public list keyed by owner. Later enrollment leaves that entry in force.
- A public and a private block are two rules. One rule over both would admit a publicly blocked owner with no private entry.
- The wallet derives its salt per ring from its viewing key, so an auditor that holds the nullifier secret cannot derive another ring's salt.
- Private lists serve one ring. A source of a salted list must carry the ring's id as its private ring id. A curator that serves several rings therefore keeps one registry per ring.
- A list writer reads an enrolled owner's salt through `getListSalt`, which checks the salt against the credential's tag and never returns the nullifier secret.
- A private write proves the owner's credential and its address in tree 0. A write for an owner whose address waits in the tree 0 queue waits too. A write that names an asset whose mint hashes to its member needs no credential.

## Audit credentials

- A credential contains one owner's ring id, owner identity, nullifier key and list tag. It also holds the auditor key, an ephemeral key and the ciphertext that seals the nullifier secret and the list salt.
- It is an SPP data note owned by the ring's credential PDA, `[b"credential"]` under the ring program. Only `Enroll` signs for that PDA, and no instruction spends or replaces the note.
- Its address derives from `Poseidon(CRCA, ring_id, member)` in tree 0, so one owner has one credential per ring. A key or viewing key change makes no second identity.
- `Enroll` needs the owner's signature, and a program signs its PDA through CPI. Any payer may fund it, and Ring RPC can relay it for a wallet with no SOL.
- The program builds the credential from the ring account and the signing owner. It verifies `RegisterKey` over that value and refuses the zero nullifier key. A proof for another ring, member or auditor fails.
- The program passes SPP the same credential as the output, so a valid `RegisterKey` proof authorizes no other note. A second `Enroll` fails on the existing address.
- A proof reads a credential present by its state inclusion under a root of the SPP tree that holds it. No address proof and no owner-specific account enters the transaction.
- A proof reads an owner absent by a strict gap around its address in tree 0's nullifier tree, under one address root per proof.
- A credential is usable once a state root that holds it passes SPP's root rules. Its address enters tree 0's queue at `Enroll` and a root only when a forester applies the batch.
- A paused or full state tree keeps its last root, so its credentials stay readable.
- The ciphertext stays in the `Enroll` transaction's plaintext output data. Ring RPC rebuilds every credential from finalized `Enroll` history after a restart.

## Viewing keys

- A wallet's current viewing key lives in zolana's user record, one account per wallet across every ring. No ring account holds a viewing key.
- `UPDATE_KEYS` rotates the viewing key, and the user registry refuses a change of the nullifier key.
- A sender's SDK reads the record at its canonical address and checks its owner and key encoding. It refuses a record whose nullifier key differs from the credential.
- A wallet keeps every replaced viewing key in its viewing history, so notes sealed to an older key still open.

## Root history

- A registry keeps its newest roots, each with a revision.
- A graced update keeps the outgoing root valid for the grace period, so a proof in flight under it still lands.
- An immediate update retires every earlier root at once, and every proof under them fails.
- A graced update waits while the oldest kept root is still valid, so it never drops a valid root.
- The program classifies each policy write from its masks. A write that touches a list a rule can read or mint settings is immediate, and any other write is graced.
- Every such list write therefore fails proofs in flight at that root, an allowlist addition included. Those proofs prove again.

## Absence floor

- A private write proves its owner's address under one tree 0 root. The Storage program reads that root's append sequence from tree 0's history. It raises the registry's `absence_floor` to that sequence with the new policy root, in one instruction.
- The instruction carries the claimed sequence, and the program refuses it when it differs from the root's sequence, before the proof.
- A frame that reads salted lists names a tree 0 root at or above the highest floor of the sources it reads them through. A lower root fails with `AbsenceRootBelowFloor`.
- Every owner with a private entry proved its address at or below the floor. Every accepted root therefore holds that address, and no such owner proves absence.
- An owner whose enrollment waits in the queue has no private entry, so its proven absence hides none.
- A public write leaves the floor unchanged, and the floor never falls.

## Live roots

- The program checks each registry account against the address the ring account binds, then reads its root live.
- A proof names a root by its revision, and the program reads that root. The prover picks the revision, never the root.
- A direct sender that meets a retired root reads the newest root and proves again. Ring RPC never proves a relay again, so a relay that meets a retired root fails and the wallet sends a new request.
- A delegate transfer and a merge read no policy root, so a policy update cannot fail them. Every transfer and deposit reads tree 0 and at least one credential state tree.
- An owner-signed merge reads no credential, and a hidden owner's merge reads one state root and no address root.
- An audit-only ring with no records reads the credential roots alone.

## How fast a change binds

- A graced write is in the newest root at once. A new proof can still name the old root for the grace period.
- Ring RPC checks reader grants against the newest root, so a graced grant revocation stops reads once its batch lands.
- A curator's immediate write stops a subscriber ring at once, since the ring reads the curator's roots at transaction time.
