# Storage

Storage keeps tree roots for rings and curators, and verifies the proof behind every root it accepts. Start with [the instruction entry point](src/lib.rs). The layouts and `StorageError` live in `custom_ring_interface::{storage, tracking}`, and the instruction data in `custom_ring_interface::storage_instruction`.

## Policy registries

A creator makes a registry at the PDA `[b"storage", creator, registry_id]`. The creator and the payer both sign, and the creator becomes the first authority. Initialization fixes the grace period. The initial root holds only the tree sentinel.

An update carries record writes and an apply proof. The program checks the authority signature, turns each write into its tree entry, and chains the entries in order from a start that binds the registry address and the expected revision. The proof binds the old root and leaf index to their replacements.

The program classifies an update from its masks. A write touching a list a rule can read, or mint settings, takes effect with zero grace: it clears every earlier root in the same instruction and runs at a full history, so an older root never outlives it. Every such write fails proofs in flight at that root, and they prove again. A write touching only other lists, such as Reader, gives the outgoing root a fixed expiry slot, saturating at `u64::MAX`, and fails if it would replace an unexpired root. `StorageRegistry::root` is the one rule for which root a revision names at a slot.

The authority hands the registry to a new authority with `UpdateAuthority`. Both keys sign, so a typo cannot lock the registry. The old authority loses every right at once.

## Salted lists

A registry created with a nonzero `tracking_registry`, a ring's own or a curator's, may back a salted list. Its writes are ordinary record writes under salted member keys. A zero grace update on it takes the pinned registry as a third account and stores that registry's newest revision as `tracking_floor`, and a ring refuses a frame reading the source under an older tracking root through `LiveRoots::tracking`. A stale root could otherwise prove a blocked owner unenrolled. The ring also compares `tracking_registry` to its own pin, because this program does not know which ring a source serves.

## Tracking registries

A ring creates one tracking registry at `[b"tracking_registry", creator, ring_id]`, pinning its ring id and auditor key. Neither the seeds nor the ring id authenticate it: anyone can create one naming any ring, and only the address a ring pins in its policy counts.

`Enroll` needs the owner's signature, a program signing its PDA through CPI, and any payer may fund it. A first enrollment verifies a `RegisterKey` proof in the same instruction and creates the owner's `TrackingAuthorization`. `Enroll` only reads the registry, so enrollment traffic takes no write lock on it. The program supplies the member, the ring id and the auditor key to the statement. A later `Enroll` carries no proof and moves only the viewing key and the revision. The nullifier key, list tag and ciphertext are final.

`ApplyEnrollments` is permissionless. The applier names up to `APPLY_BATCH` authorization accounts in any order, and the program computes each entry from account state, so an applier chooses only which accounts and in what order. A stale proof fails and the accounts stay pending for the next applier. Nothing grants anything while pending, because every check reads the root.

Tracking roots keep `TRACKING_GRACE_SLOTS` and a full history makes an apply wait, so a flood of applies never evicts a root an in-flight transfer names. A rotation stales a proof that names the rotated account, so an applier leaves out an account that changed recently.

The tracking tree is taller than a policy tree because anyone can pay to fill it and no tree replaces a full one. A first enrollment past capacity stays pending and grants nothing, and no other entry waits for it, since an applier names its accounts. Rotations of enrolled owners need no free leaf.

The tracking registry stays separate from the policy registry because authority revocation must not race permissionless enrollment: a stale apply proof fails on revision, so one shared tree would let enrollment traffic delay a block.

`OwnerGrant` lets a program owner name a reader through CPI, since a PDA cannot sign an off-chain read. A wallet signs its Reader grant, and the record writer takes that grant only on the wallet's signature. The owner alone writes the grant account and can revoke it. Ring RPC reads the account at the grant's address, which names the registry, owner and reader.

## Limits

An enrollment is public: anyone can see a wallet enrolled on a ring. Accounts created here are never closed, which is what prices a flood of first enrollments. The program verifies no policy. A consumer reads a root and authenticates the registry, the rules and the action before it acts.

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
