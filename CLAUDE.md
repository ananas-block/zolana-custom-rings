# Zolana Custom Rings Contributor Notes

@zolana/CLAUDE.md

The zolana notes above apply here, with their paths read under `zolana/`.

## Repository

- `zolana/` is the zolana submodule. Ring crates take zolana crates by path
  into it, so a zolana change and its ring change build together locally. Land
  the zolana side first, then move the pin with `just zolana-bump <commit>`.
- The layout mirrors zolana: `programs/custom-ring`, `program-libs/{interface,
  policy,member-registry}`, `sdk-libs/{client,indexer,sdk,transaction,ts}`,
  `program-tests/custom-ring`, `services/{photon,ring-rpc}`, `cli`, `xtask`.
- The ring verifying keys are committed in `program-libs/interface/src`, and
  `just check-custom-ring-keys` diffs them against the ring prover's export of
  the keys `prover/ring/proving-keys.lock` pins.
- The Go module `prover/` holds the ring circuits in `prover/circuits` and
  builds the ring prover, `just build-prover-server`. `prover/cmd/prover`
  registers no ring circuit, so the ring prover serves the SPP circuits only.
  The justfile exports its `PROVER_BIN`.
- Shared vectors stay in `zolana/test-vectors`. Vectors only ring code reads
  live in `test-vectors/`.

## Common Commands

```bash
just check-all
just clippy
just test-hermetic
just test-custom-ring-validator
just check-custom-ring-keys
just zolana::build-programs
```
