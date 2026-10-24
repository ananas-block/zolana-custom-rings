# Custom rings

A custom ring is a Solana program that governs the zolana shielded notes
tagged with its program id. The zolana shielded pool (SPP) moves a ring note
only on an instruction the ring program signs. Every transfer proves that the
ring's auditor can open it, and a policy ring also proves its rule table. A
confidential ring hides assets and amounts. An anonymous ring also hides
senders and recipients.

## Split with zolana

- SPP holds the notes, vaults, trees and nullifiers and verifies its own
  proofs. Its ring instructions require the ring's `ring_auth` PDA to sign.
- The ring program checks the ring proofs, signers and controls, then invokes
  SPP as `ring_auth`. It depends on zolana libraries, never on the SPP program.
- The ring prover is the zolana prover built from the Go module `prover/`,
  which holds the ring circuits.
- zolana's Photon has no ring code. `services/ring-indexer` indexes the ring
  state and forwards every other JSON-RPC call to Photon.
- `zolana/` pins zolana. A change to both lands in zolana first, then
  `just zolana-bump <commit>` moves the pin.

## Setup

```bash
git clone --recursive https://github.com/helius-labs/zolana-custom-rings.git
just check-all && just test-hermetic
```

The build needs the Rust and Solana toolchains zolana pins, Go at the version
`prover/go.mod` names, and `just`. `just fetch-custom-ring-keys` downloads the
proving keys the lockfiles pin. The `test-custom-ring-*` suites start a local
validator, Photon, the ring indexer and the ring prover.

## Use

`zolana-ring new`, `deploy` and `init` create a ring, deploy its program and
fix its auditor key, tier and policy. Members pay with `zolana-ring transfer`
and `merge`, or through the Rust and TypeScript SDKs.

## Limits

- The upgrade authority can replace every check of the ring program.
- No instruction replaces the auditor key after `CreateConfig`.
- A paused ring, or one SPP governance has not activated, moves no note.
