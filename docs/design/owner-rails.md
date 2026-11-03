# Owner rails

SPP authorizes a ring spend in one of four ways. The instruction, the ring mode and one frame flag pick the rail, and each rail gives the policy a different sender. [Spec](../spec.md)

## The rails

1. **Signer rail.** Each input owner signs the Solana transaction, and the statement binds the deduplicated owner run. Slot 0 can be a dummy, so a public-funded transfer stays valid. A policy needs at least one owner and screens each one as a sender.
2. **In-proof rail.** The owner signs the SPP message inside the proof of SPP's anonymous rail, and SPP hides the owner. The transfer statement publishes the owner as the sender. Any payer sends the transaction.
3. **Anonymous rail.** A hidden owner signs inside the SPP proof, and public co-owners can sign the transaction beside it. Spent note zero names the hidden sender, and each co-owner is a sender too. The statement carries no sender. A frame with only public owners belongs to the confidential family.
4. **Authority rail.** The ring PDA moves notes with no owner signature. The delegate signs instead, and every note stays in the ring.

The anonymous entry key spends one owner's notes and takes no co-owner. Every key on the other rails holds each live input to the ring.

## Why the in-proof rail exists

- Ring RPC relays and pays for a wallet spend unless it has a deposit leg or needs an outside co-signer. A relayed anonymous or confidential transfer names no owner signer, its owner signs inside the proof.
- Zolana's in-proof owner circuit serves default-ring transfers only. SPP's anonymous rail verifies the owner's Ed25519 signature inside the proof on ring transfers, and the ring uses it with no default owner tag.
- Follows the maintainer's suggestion; keeps no new SPP circuit.
- With it, one wallet signature over the message hash lets Ring RPC prove, pay and send.

## The rule that makes it sound

- An in-proof owner could spend nothing while Solana owner signers spend the inputs. The policy would then screen the wrong sender.
- The ring program refuses any owner signer on the in-proof rail. Every input is then SPP's hidden owner's.
- SPP hides that owner. The transfer proof holds every spent UTXO to the sender the statement publishes and reopens SPP's `private_tx_hash` over the same inputs and outputs. The hidden owner is then the published sender, and the policy reads it as the sender.
- The owner is public on a confidential ring, so the anonymous rail's party separation does not apply. The ring program refuses a co-signer that is the owner.

## Limits of the in-proof rail

- It spends ring notes only. A default-ring input makes SPP publish the owner it hides, and the confidential key refuses it.
- SPP refuses an exit to the sender's own default-ring identity on a ring spend. Exits keep their scheme 3 data, and SPP publishes each exit owner.
- The confidential key holds one input class per output count. The program refuses a transfer that publishes more inputs than the class holds.
- The envelope carries a hash per published input on every rail. The SDKs refuse a wider shape as unkeyed on every rail, and the sender merges first. A policy ring fits a full 16-output frame on neither rail unless it escrows keys.

## Why the signer rail stays

- It takes several owners in one transfer, and each signs the transaction. The auditor reads a hash per spent note.
- It serves owners and operators who send their own transaction, the operator CLI and the tests included.

## What each rail publishes

- Signer rail: the owner signer, each output's recipient viewing key and, on a policy ring, the owner's identity and each output's owner identity.
- In-proof rail: the owner key in the transfer data in place of the signer, and the outputs as the signer rail publishes them.
- Anonymous rail: a view tag on each recipient or dummy slot, each exit owner, the change bits and the sender bundle with its tag. Each public co-owner signs in the open, and a default-ring spend also publishes the hidden owner's key.
- Authority rail: the delegate, and the outputs as the signer rail publishes them.

## A wallet with only its owner key

- The signer rail lets the owner pay. No check stops an in-proof owner paying its own transaction. Neither rail serves an anonymous ring.
- [Flow 5](../spec.md#5-user-merge) states the merge route for each ring mode.

## Separation from the hidden owner

- On the anonymous rail SPP separates the hidden owner only from the owner signers.
- The ring's transfer proof also shows the payer, the co-signer and the withdrawal destination differ from the hidden owner. It shows the hidden owner is outside the co-owner run.
- No layer checks a key that is only linked to the owner.
