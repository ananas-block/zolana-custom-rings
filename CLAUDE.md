# Zolana Custom Rings Contributor Notes

@zolana/CLAUDE.md

The zolana notes above apply here, with their paths read under `zolana/`.

## Repository

- `zolana/` is the zolana submodule. Ring crates take zolana crates by path
  into it, so a zolana change and its ring change build together locally. Land
  the zolana side first, then move the pin with `just zolana-bump <commit>`.
- The layout mirrors zolana: `programs/custom-ring`, `program-libs/{interface,
  policy,member-registry}`, `sdk-libs/{client,indexer,sdk,transaction,ts}`,
  `program-tests/custom-ring`, `services/{ring-indexer,ring-rpc}`, `cli`, `xtask`.
- The ring verifying keys are committed in `program-libs/interface/src`, and
  `just check-custom-ring-keys` diffs them against the ring prover's export of
  the keys `prover/ring/proving-keys.lock` pins.
- The Go module `prover/` holds the ring circuits in `prover/circuits` and
  builds the ring prover, `just build-prover-server`. `prover/cmd/prover`
  imports `prover/ring` to register ring circuits alongside the SPP circuits.
  The justfile exports its `PROVER_BIN`.
- Shared vectors stay in `zolana/test-vectors`. Vectors only ring code reads
  live in `test-vectors/`.

## Ownership after the split

- Zolana owns wallet identity and key derivation, X25519 primitives, SPP circuits
  and programs, and generic prover/Photon extension hooks. Fix those upstream
  first, then update this repository's `zolana` pin to the merged commit.
- Custom rings owns ring circuits, policies, disclosures, the ring program,
  SDKs, CLI, indexer and auditor RPC. Ring integration failures belong here
  unless they reproduce in the underlying Zolana functionality.
- Examples consume `@heliuslabs/zolana-custom-rings` for ring operations and
  `@heliuslabs/zolana` for core wallet functionality. Keep both dependencies on
  compatible revisions; the submodule identifies the tested core revision.
- Use `ed25519DerivationMessage(publicKey)` for browser-wallet signing. The
  signed off-chain message derives the existing identity; the bare payload does not.
- The ring key lockfile owns artifact names, sizes and hashes. Publish its exact
  prepared files before merging a rotation. The public Zolana key release hosts
  these artifacts while this repository is private; downloads need no credentials.

## Common Commands

```bash
just check-all
just clippy
just test-hermetic
just test-custom-ring-validator
just check-custom-ring-keys
just zolana::build-programs
```
