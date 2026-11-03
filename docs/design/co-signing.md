# Co-signing and limits

A ring bounds what moves with three mechanisms: co-signer approval in the ring program, outflow limits in the transfer proof, and window limits in Ring RPC. [Spec](../spec.md)

## Who must co-sign

- An operation demands each of its classes that some co-signer account covers.
- The transfers class covers every transfer, delegate move and merge. The deposits class covers a deposit and a transfer with a deposit leg. The withdrawals class covers a transfer with a withdrawal leg.
- The frame's exempt flag waives the withdrawals class. The program folds the legs into each public slot's gross withdrawal. The transfer proof then holds that gross at or below the asset record's withdrawal threshold. A mint without a record admits no exempt withdrawal.
- One co-signer whose scope covers every demanded class signs. A transfer that only crosses a co-sign bound takes any co-signer. With no co-signer account, that transfer fails.
- The co-signer differs from every owner signer, the in-proof owner, the hidden owner and the delegate. A public co-owner signs as an owner and counts as an owner signer.
- Ring RPC co-signs only with its own key. Where the demanded co-signer is an outside key, a wallet sends its transfer, deposit or merge itself, and a managed merge cannot run.

## Outflow limits, in the transfer proof

- One owner's debit of an asset is what its spent notes held of the asset, less what ring outputs return to it. A debit never falls below zero.
- An exit counts as leaving, whoever receives it. A credit never moves between owners.
- One owner's notes add up across nullifier keys, because the debit keys on owner identity.
- Each debit stays at or below the asset's cap. A zero cap or co-sign bound turns that check off.
- A debit above the asset's co-sign bound sets the approval bit, and the program then demands a co-signer.
- A key screens a fixed number of owners under a policy, and a transfer with more distinct owners is refused.
- A transfer spending notes of two owners cannot carry a positive public net of an asset either owner spends. An unrelated asset stays allowed.

## Window limits, in Ring RPC

- Each asset's record holds a sender cap, a volume cap, a deposit cap and a withdrawal cap, each with its own window in slots. A zero cap is no cap.
- The sender cap counts one owner's debit. The volume cap counts what the ring transfers, deposits and withdraws.
- Ring RPC checks them when it decides whether to co-sign, and the program checks only the co-signature.
- Ring RPC derives a transfer's debits from the frame it signs, with the auditor key. An input it cannot name refuses with `LimitsUnavailable`, and the wallet retries after ingestion. A ring whose auditor key it does not hold refuses the limited co-signer.
- A message co-signed from its frame holds one ring transfer, and a second relevant instruction refuses. The check covers the complete account list, and a message with lookup table accounts refuses.
- `owner_debits` in `program-libs/policy/src/debit.rs` is the Rust computation, and the TypeScript SDK and the circuit mirror it. Reservations key on ring, owner and asset. One message signature holds one row per nonzero debit or public leg, each owner and asset once.
- Ring RPC reserves flows when it co-signs and fails closed, see [Flow 9](../spec.md#9-co-signer-limits-configuration). A deposit or a delegate move reserves only once its other signers sign, so an unsigned relay holds no allowance. Ring RPC's store serializes admission, so no allowance is granted twice.

## What passes them

- Window limits apply only to operations that demand a co-signer and that Ring RPC co-signs.
- The limits bind every operation of a class, such as transfers, only when Ring RPC is the one co-signer that covers that class.
- With no co-signer for its classes, a transfer below the co-sign bound never counts.
- A co-signer key outside Ring RPC whose scope covers the demanded classes signs with no window limit.
- Each signing key is its own sender, so one person with many keys passes a sender cap once per key.
- Outflow limits and amount guards sum one transfer. A payment split across transfers passes each part.
- A deposit leg can fund what returns to an owner, so it lowers that owner's debit. The debit stops at zero.
- The delegate rail runs no debit check.

## Real-world controls

- A cap per transfer and asset holds.
- Dual control above an amount holds on owner transfers, and the transfer publishes the approval bit. A delegate move sets no approval bit.
- A cap per customer per window holds only on co-signed operations.
- A cap per person across keys does not hold.
