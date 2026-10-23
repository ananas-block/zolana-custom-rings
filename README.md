# Custom rings

A custom ring is a Solana program that governs the shielded notes tagged with
its program id. The notes live in the zolana shielded pool (SPP). SPP moves
them only on an instruction the ring program signs. The ring program signs a
transfer only after the ring's proofs verify. The audit proof of every transfer
shows that the ring's auditor can open it. A policy ring also proves its rule
table for every transfer. An audit-only ring proves the audit alone. A
confidential ring hides assets and amounts and shows its senders. An anonymous
ring also hides senders and recipients.

## Roles

The upgrade authority deploys and upgrades the ring program and creates its
config. The config authority writes the authority lists, grants readers, sets
the co-signer, and pauses or resumes the ring. `CreateConfig` gives this role
to the upgrade authority that signs it. `SetAuthority` hands it to another key.

The auditor holds the X25519 key the config pins and reads every transfer. Its
key authorizes no spend. The ring RPC holds the auditor key and serves each
reader the config authority grants.

Members own the ring notes, sign their own transfers and set their own
membership in the member lists. A co-signer is a second Solana key that the config
demands for the operation classes it names. On a confidential policy ring the
upgrade authority can set a delegate once. The delegate moves member notes
inside the ring with nullifier keys escrowed to the auditor. It cannot
withdraw. A curator is another ring whose lists a policy ring reads.

## Split with zolana

SPP holds the notes, the deposited SOL and SPL tokens, the trees and the
nullifiers. It verifies its own transfer and merge proofs. It keeps the ring
instructions `ring_transact`, `ring_authority_transact`, `ring_deposit` and
`ring_merge_transact`. SPP stores the ring's config at the `ring_auth` PDA of
the ring program. Each ring instruction requires that PDA to sign. A plain
SPP instruction binds ring id zero and cannot spend a ring note. SPP governance
owns the activation of a ring and its delegate rail.

The ring program decides what settles. It verifies the ring proofs, checks the
signers and the ring's controls, then invokes the SPP ring instruction signed
as `ring_auth`. It depends on `zolana-interface`, never on the SPP program.

The ring prover is the zolana prover built from the Go module `prover/`. That
module holds the ring circuits and starts the prover through zolana's
`app.Run`. The zolana prover takes outside circuits through
`common.RegisterExtension` and their keys through `provingkeys.Register`.
`services/photon` is the zolana Photon with the ring indexer extension.

The `zolana` submodule pins zolana. The ring crates, the Go module and the
TypeScript workspace take zolana by path from the submodule. A change on both
sides therefore builds together. The zolana side lands first, then
`just zolana-bump <commit>` moves the pin. CI refuses a pin that is not on
zolana `main` or a `release/*` branch.

## Repository

`programs/custom-ring` is the ring program. `program-libs/interface` holds its
account layouts, instruction data and committed verifying keys.
`program-libs/policy` defines the lists and the rule table. `sdk-libs/sdk`
builds, proves and submits ring operations in Rust. `sdk-libs/ts` is the
TypeScript SDK. `sdk-libs/client` is the auditor side. `services/ring-rpc`
is the ring RPC. `cli` builds the `zolana-ring` operator binary. `examples`
holds one `ring.toml` per worked example.

## Setup

Clone with the submodule:

```bash
git clone --recursive https://github.com/helius-labs/zolana-custom-rings.git
```

The build needs the Rust toolchain zolana pins, the Solana platform tools
(`SBF_TOOLS_VERSION`) and Go at the version `prover/go.mod` names. The recipes
also need `just`, `cargo-nextest`, `python3` and the Solana CLI. The TypeScript
SDK needs Node 24 or later.

`just check-all`, `just clippy` and `just test-hermetic` need nothing running.
`just test-custom-ring` runs the Go circuit tests. `just test-ts` checks the
TypeScript SDK. The `test-custom-ring-*` suites and `test-ts-e2e` start a local
validator, Photon and the ring prover. The `zolana` module runs the zolana
recipes, as in `just zolana::build-cli`. A `.env` with `ZOLANA_PORT_OFFSET`
shifts every service port, as in zolana.

Proving keys are public setup output. `just fetch-custom-ring-keys` downloads
the ring keys `prover/ring/proving-keys.lock` pins and the SPP ring keys the
suites need from the zolana lockfile. It refuses a file whose hash differs
from its lockfile.

## Use

An operator brings a ring up with `zolana-ring`:

1. `zolana-ring new` writes the ring directory, `ring.toml` and the program
   keypair. The keypair address is the program id and fixes the ring id.
2. `zolana-ring localnet` starts a local validator and the ring services.
   `zolana-ring devnet` probes the services `ring.toml` names.
3. `zolana-ring deploy` deploys the ring program of the release the CLI was
   built from. The authority keypair `ring.toml` names becomes the upgrade
   authority.
4. `zolana-ring init` creates the config, which fixes the auditor key, the tier
   and whether the ring is anonymous. It then pins the policy of a policy ring
   and registers the ring with SPP.
5. On a pool without permissionless ring activation, SPP governance activates
   the ring with `set_ring_activation`. No note moves before it.

`zolana-ring --help` lists the commands that run the ring after `init`. A
member pays inside the ring with `zolana-ring transfer` and merges its notes
with `zolana-ring merge`. The Rust and TypeScript SDKs do the same.
`just release <tag> --upload` publishes the ring program, the ring keys, the
ring RPC and `zolana-ring` as one release.

## Limits

The upgrade authority can replace every check of the ring program. Renouncing
it after `init` freezes the checks, not the lists or the controls the config
authority writes.

No instruction replaces a lost or leaked auditor key after `CreateConfig`.

A paused ring moves no note, withdrawals included, because every exit runs
through an SPP ring instruction. Only the config authority resumes it. A ring
that SPP governance has not activated, or has deactivated, moves no note
either.

Once a delegate exists, key escrow runs for the life of the ring. No
instruction removes the delegate.
