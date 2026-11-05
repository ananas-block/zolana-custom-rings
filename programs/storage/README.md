# Storage

Storage keeps tree roots for rings and curators, and verifies the proof behind every root it accepts. Start with [the instruction entry point](src/lib.rs). The layouts and `StorageError` live in `custom_ring_interface::{storage, owner_grant}`, and the instruction data in `custom_ring_interface::storage_instruction`. Enrollment lives in the ring program, as SPP state.

## Policy registries

A creator makes a registry at the PDA `[b"storage", creator, registry_id]`. The creator and the payer both sign, and the creator becomes the first authority. Initialization fixes the grace period. The initial root holds only the tree sentinel.

An update carries record writes and an apply proof. The program checks the authority signature, turns each write into its tree entry, and chains the entries in order from a start that binds the registry address and the expected revision. The proof binds the old root and leaf index to their replacements.

The apply proof classifies an update, and the statement binds its [restrictive](../../docs/design/records-and-roots.md#root-history) bit.

A restrictive batch takes effect with zero grace. It clears every earlier root in the same instruction, even at a full history, so an older root never outlives it. Proofs in flight at an earlier root prove again.

Any other batch, an allowlist addition or a Reader grant, gives the outgoing root a fixed expiry slot, saturating at `u64::MAX`. Over a full history it evicts the oldest kept root. Every kept root reads each policy field no more permissively than the newest root. A proof under a kept root therefore admits no transfer the newest root refuses. `StorageRegistry::root` is the one rule for which root a revision names at a slot.

The authority hands the registry to a new authority with `UpdateAuthority`. Both keys sign, so a typo cannot lock the registry. The old authority loses every right at once.

## Private writes

A registry created with a nonzero `private_ring_id`, a ring's own or a curator's, may back a salted list of that ring. Its private entries are ordinary record writes under salted member keys, and each proves the owner's audit credential. The ring refuses a frame that reads a salted list through a source whose `private_ring_id` is not its own. This program does not know which ring a source serves.

The program classes each write from its masks, and no caller flag selects the class. A write that touches no private list needs no credential proof. A private write that names an asset entry passes when the mint hashes to the written member. Every other private write sets its bit in `credential_writes`. The apply proof must then show the owner's salted key, its credential's list tag, and the credential's state and address inclusion.

A private write names the ring program and the address root's append sequence. The program checks the ring program against `private_ring_id`, reads the root's sequence from tree 0's history and refuses a different claim, all before the proof. After the proof it raises `absence_floor` to that sequence together with the new root, and a refusal writes neither. A ring accepts an address root for a salted read only at or above the floor. An owner with a private entry therefore never proves itself unenrolled. No proof covers a private write for an owner whose address still sits in tree 0's queue. Ring RPC's writer waits for the forester and refuses once its wait ends.

A public update carries an empty credential read and no tree accounts, and a registry with a zero `private_ring_id` refuses every private write.

## Owner grants

`OwnerGrant` lets a program owner name a reader through CPI, since a PDA cannot sign an off-chain read. A wallet signs its Reader grant, and the record writer takes that grant only on the wallet's signature. The owner alone writes the grant account and can revoke it. Ring RPC reads the account at the grant's address, which names the ring program, owner and reader.

## Limits

The program verifies no policy. A consumer reads a root and authenticates the registry, the rules and the action before it acts.

## Tests

Build and run the lifecycle test from the workspace root.

```sh
just build-storage-program
cargo test --locked -p storage-program --test lifecycle
```

Tests that settle a real proof read [proofs.json](tests/proofs.json) and are ignored until it is regenerated against the rotated keys. The others seed accounts and stop at the proof check, so they show the checks ahead of the pairing and never that a proof settles. To replace the fixtures, install the pinned ring proving keys and run the generator from `prover/`. The proofs bind the registry address, and the test refuses a fixture made for another address.

```sh
STORAGE_REGISTRY="$(jq -r .registry ../programs/storage/tests/proofs.json)" \
REQUIRE_RING_KEYS=1 go test ./ring -run '^TestStorageFixtures$' -count=1
```

`ZOLANA_PROVER_KEYS_DIR` points the generator at another key directory.
