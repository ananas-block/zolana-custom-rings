# Combined client prover deployment plan

This plan is for `../zolana-infra`; it does not change that repository. The
client prover can serve Zolana's native transfer and merge circuits together
with custom ring circuits. `zolana-custom-rings` builds the combined binary from
`prover/cmd/prover` and owns its image and ring key release. Zolana continues to
own its native keys. The forester prover keeps its Zolana image and separate
Redis queue.

## Prerequisites

1. Pin a Zolana commit containing the generic extension release-key downloader.
   Its on-demand fetch must enforce the extension lockfile's byte size and
   SHA-256. Keep Zolana's native object-store source unchanged.
2. Confirm the 96 bare `.key` files in the
   [mint-record key release](https://github.com/helius-labs/zolana-custom-rings/releases/tag/mint-record-keys-v1)
   match `prover/ring/proving-keys.lock`. Run
   `python3 tools/check_ring_key_assets.py <downloaded-assets-dir>` on the
   complete directory before using it as a local cache.
3. Build and smoke-test the `ring-prover` image from this repository's
   `prover/Dockerfile`; record its immutable image digest and source commit.
   The image embeds both lockfiles and no proving-key bytes. The combined image
   is built here; Zolana does not import this repository.

## Infra change to prepare

- Set only the client-facing `prover` service's `PROVER_IMAGE` to the recorded
  `zolana-ring-prover` digest. Leave `FORESTER_PROVER_IMAGE`, its circuit filter,
  and its separate Redis queue alone. In local `docker-compose.yml`, remove or
  override the inline native-only `prover.build` when selecting the published
  image; `docker-compose.remote.yml` already selects an image through
  `PROVER_IMAGE`.
- Keep the client prover's `--auto-download true` and a writable, persistent
  `/proving-keys` cache. Permit egress to Zolana's native key object store and
  this repository's pinned ring-key release. Size the cache for the shapes the
  service actually uses; the full ring catalog alone is about 7.2 GB.
- Roll out by immutable digest, preserving the old client image digest for
  rollback. Do not change the forester or its key cache as part of this step.

## Acceptance

1. From one client prover endpoint and the same Redis queue, submit a known
   native transfer or merge request and a known custom ring request. Require
   both proofs to verify against their respective committed verifying keys.
2. Start with empty key caches. Confirm each request fetches only its pinned
   key, a second request reuses the cached key, and a corrupted cached key is
   rejected and replaced only when automatic download is enabled.
3. Check `/proving-keys` for both key families and confirm that failed
   size/SHA-256 checks never install a key. Record proof latency, memory, and
   cache use, then repeat after a service restart.
4. Confirm the forester still proves its own batch request using its unchanged
   image and queue. Roll back the client image digest if either family fails.

The current devnet-d client prover is Aeglos CPU inside a Nitro Enclave. That
path needs separate ring-circuit, key-loading, attestation, and resource
qualification before it can be described as serving custom rings. The combined
plaintext client image does not establish Nitro support.
