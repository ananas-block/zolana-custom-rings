#!/usr/bin/env bash
set -euo pipefail

# gnark's Setup is non-deterministic, one run writes the proving key, the
# committed Rust verifying key and the ring lockfile entry together.
# generate_keys_custom_ring.sh [keys_dir] [verifying_key_dir]

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
keys_dir="${1:-$repo_root/zolana/prover/server/proving-keys}"
mkdir -p "$keys_dir"
keys_dir="$(cd "$keys_dir" && pwd)"
vkey_dir="${2:-$repo_root/program-libs/interface/src}"
lock="$repo_root/prover/ring/proving-keys.lock"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

prover="$repo_root/target/prover-server"
(cd "$repo_root/prover" && go build -o "$prover" ./cmd/prover)
cargo build -q --manifest-path "$repo_root/zolana/Cargo.toml" -p xtask --target-dir "$repo_root/zolana/target"
xtask="$repo_root/zolana/target/debug/xtask"

release_flags=()
for key in $(python3 -c 'import json, sys; print(" ".join(sorted(json.load(open(sys.argv[1]))["keys"])))' "$lock"); do
    stem="${key%.key}"
    circuit="${stem//_/-}"
    module="${stem#custom_ring_}_verifying_key.rs"
    echo "Generating ${circuit} -> ${keys_dir}/${key}"
    "$prover" "setup-${circuit}" --output "$keys_dir/$key" --vk-out "$tmp_dir/$stem.vkbin"
    "$xtask" bsb22-vk "$tmp_dir/$stem.vkbin" "$keys_dir/$key" "$vkey_dir" "$module"
    rustfmt --config-path "$repo_root/rustfmt.toml" "$vkey_dir/$module"
    release_flags+=(--release "$key")
done

python3 "$repo_root/zolana/prover/server/scripts/generate_lockfile.py" "$keys_dir" \
    --out "$lock" "${release_flags[@]}" --only-release

echo "Done. Ring proving keys in ${keys_dir}, verifying keys in ${vkey_dir}"
