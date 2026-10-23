# Zolana custom rings workspace
set dotenv-load

# zolana's recipes run inside the submodule, `just zolana::build-programs`.
mod zolana

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")

# Per-clone port isolation, the same scheme and .env as zolana's justfile.
export ZOLANA_PORT_OFFSET := env_var_or_default("ZOLANA_PORT_OFFSET", "0")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", `echo $((8899 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-photon-port := env_var_or_default("ZOLANA_LOCALNET_PHOTON_PORT", `echo $((8784 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-prover-port := env_var_or_default("ZOLANA_LOCALNET_PROVER_PORT", `echo $((3001 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-ring-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RING_RPC_PORT", `echo $((8785 + ${ZOLANA_PORT_OFFSET:-0}))`)
stop-localnet-backends := "for port in " + localnet-rpc-port + " $((" + localnet-rpc-port + " + 1)); do lsof -t -i tcp:$port -s tcp:listen 2>/dev/null | xargs kill -9 2>/dev/null || true; done"
localnet-rpc-url := env_var_or_default("ZOLANA_LOCALNET_URL", "http://127.0.0.1:" + localnet-rpc-port)
localnet-photon-url := env_var_or_default("ZOLANA_LOCALNET_PHOTON_URL", "http://127.0.0.1:" + localnet-photon-port)
localnet-prover-url := env_var_or_default("ZOLANA_PROVER_URL", "http://127.0.0.1:" + localnet-prover-port)
photon-bin := env_var_or_default("ZOLANA_PHOTON_BIN", "target/debug/photon")
spp-keys-dir := env_var_or_default("ZOLANA_SPP_KEYS_DIR", "zolana/prover/server/proving-keys")
ring-keys-lock := "prover/ring/proving-keys.lock"
custom-ring-keys := `python3 -c "import json;print(' '.join(sorted(json.load(open('prover/ring/proving-keys.lock'))['keys'])))"`

export ZOLANA_PROVER_URL := localnet-prover-url
export PROVER_INDEXER_URL := localnet-photon-url
# Every prover a recipe here starts is the ring prover.
# Any genesis address works, the shared ring binary serves it.
export CUSTOM_RING_PROGRAM_ID := env_var_or_default("CUSTOM_RING_PROGRAM_ID", "9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh")
export PROVER_BIN := justfile_directory() / "target/prover-server"

default:
    @just --list

# === Build ===

build-programs: zolana::build-programs
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    SBF_TOOLS_VERSION={{sbf-tools-version}} zolana/tools/build-programs.sh \
        --manifest-path programs/custom-ring/Cargo.toml -- --locked --features bpf-entrypoint

build-cli:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    cargo build -p custom-ring-cli --target-dir target

build-ring-photon:
    cargo build --locked -p custom-ring-photon --bin photon --target-dir target

# The zolana and ring clis, the prover server, xtask and the ring suites' fixture Photon.
build-localnet-tools: zolana::build-cli build-prover-server
    cargo build --manifest-path zolana/Cargo.toml -p xtask --target-dir zolana/target
    cargo build --locked -p custom-ring-cli --target-dir target
    cargo build --locked -p custom-ring-photon --bin photon --features surfpool-fixture --target-dir target

build-localnet-archives dir="target/nextest-archives":
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p {{dir}}
    cargo nextest archive -p custom-ring-test-validator --test ring --test shared_sources --test policy_rules --test policy_repin --test windowed_concurrency --archive-file {{dir}}/custom-ring-test-validator.tar.zst
    cargo nextest archive -p custom-ring-sdk --test custom_ring_circuit --archive-file {{dir}}/custom-ring-sdk.tar.zst

# === Tests ===

# Everything that needs nothing running.
test-hermetic: test-program-fast test-sdk-libs test-photon

test-program-fast: build-programs
    cargo nextest run -p custom-ring-program --tests

test-sdk-libs:
    cargo nextest run -p zolana-ring-client
    cargo nextest run -p zolana-ring-indexer
    cargo nextest run -p zolana-ring-transaction
    cargo nextest run -p zolana-ring-rpc
    cargo nextest run -p custom-ring-sdk
    cargo nextest run -p custom-ring-cli
    cargo nextest run -p custom-ring-interface
    cargo nextest run -p zolana-ring-policy

test-photon:
    cargo nextest run -p custom-ring-photon

# Prover-backed client checks of the ring authority boundary.
test-client-integration: build-prover-server zolana::build-cli
    cargo nextest run -p custom-ring-sdk --features proofs --test ring_authority_boundary --test-threads 1

# Custom-ring lifecycle on a local validator (program-tests/custom-ring/tests/ring.rs).
test-custom-ring-validator filter="all()": fetch-custom-ring-keys build-prover-server build-programs zolana::build-cli zolana::ensure-smart-account zolana::ensure-surfpool
    #!/usr/bin/env bash
    set -euo pipefail
    program_ids=$(cd zolana && tools/ci/xtask.sh program-ids)
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    export SHIELDED_POOL_PROGRAM_ID
    bash tools/test-ring-controls.sh ring -E '{{filter}}'
    zolana/tools/ci/nextest-suite.sh -p custom-ring-sdk -E 'binary(custom_ring_circuit)'

# Two-ring shared policy source lifecycle on a local validator.
test-custom-ring-shared: (_custom-ring-suite "shared_sources")

# Policy rule lifecycle over the rule table pinned from ring.toml.
test-custom-ring-rules: (_custom-ring-suite "policy_rules")

# set_policy_rules rewrites the rule table of a live ring.
test-custom-ring-repin: (_custom-ring-suite "policy_repin")

_custom-ring-suite test: fetch-custom-ring-keys build-prover-server build-programs zolana::build-cli zolana::ensure-smart-account zolana::ensure-surfpool
    #!/usr/bin/env bash
    set -euo pipefail
    program_ids=$(cd zolana && tools/ci/xtask.sh program-ids)
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    export SHIELDED_POOL_PROGRAM_ID
    bash tools/test-ring-controls.sh {{test}}

# === Keys ===

# zolana's prover with the ring circuits linked in.
build-prover-server:
    #!/usr/bin/env bash
    [[ -z "${ZOLANA_PREBUILT:-}" ]] || exit 0
    mkdir -p target
    cd prover && sh ../zolana/prover/server/build-release.sh ../target/prover-server ./cmd/prover

# Go circuit and proof tests, a proof must verify under the committed VERIFYINGKEY.
test-custom-ring: fetch-custom-ring-keys
    cd prover && go test ./... -count=1

# Ring keys and transfer shapes must match their lockfiles.
fetch-custom-ring-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    keys_dir="{{spp-keys-dir}}"
    mkdir -p "$keys_dir"
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    pinned() {
        python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["keys"][sys.argv[2]]["sha256"])' "$1" "$2"
    }
    digest() {
        shasum -a 256 "$1" | awk '{ print $1 }'
    }
    fetch() {
        lock="$1" name="$2" url="$3"
        want="$(pinned "$lock" "$name")"
        [[ -f "$keys_dir/$name" && "$(digest "$keys_dir/$name")" == "$want" ]] && return
        echo "Downloading $name" >&2
        curl -fsSL --retry 3 --retry-max-time 60 --connect-timeout 10 --max-time 300 \
            "$url" -o "$temp_dir/$name"
        got="$(digest "$temp_dir/$name")"
        if [[ "$got" != "$want" ]]; then
            echo "$url hashes to $got, $lock pins $want" >&2
            exit 1
        fi
        install -m 0644 "$temp_dir/$name" "$keys_dir/$name"
    }
    release_url="${ZOLANA_RING_KEYS_URL:-$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["release"])' "{{ring-keys-lock}}")}"
    for name in {{custom-ring-keys}}; do
        fetch "{{ring-keys-lock}}" "$name" "$release_url/$name"
    done
    spp_lock="zolana/prover/server/prover/provingkeys/proving-keys.lock"
    spp_url="${ZOLANA_PROVING_KEYS_URL:-https://d3gbdb0egjwcw9.cloudfront.net}/$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["prefix"])' "$spp_lock")"
    for name in transfer_ring_1_2.key transfer_ring_2_2.key; do
        fetch "$spp_lock" "$name" "$spp_url/$name"
    done

# The committed verifying keys must be the export of the pinned proving keys.
check-custom-ring-keys: fetch-custom-ring-keys build-prover-server
    #!/usr/bin/env bash
    set -euo pipefail
    export_dir="$(mktemp -d)"
    trap 'rm -rf "$export_dir"' EXIT
    for key in {{custom-ring-keys}}; do
        module="${key#custom_ring_}"
        module="${module%.key}_verifying_key.rs"
        target/prover-server export-vk --keys-file "{{spp-keys-dir}}/$key" --output "$export_dir/$key.vkbin" >/dev/null
        cargo run -q --manifest-path zolana/Cargo.toml -p xtask -- bsb22-vk "$export_dir/$key.vkbin" "$PWD/{{spp-keys-dir}}/$key" "$export_dir" "$module" >/dev/null
        rustfmt --config-path rustfmt.toml "$export_dir/$module"
        diff -u "program-libs/interface/src/$module" "$export_dir/$module"
    done

# Rotate the ring proving keys, their verifying keys and the ring lockfile.
regen-custom-ring-keys:
    prover/scripts/generate_keys_custom_ring.sh "{{spp-keys-dir}}" "$PWD/program-libs/interface/src"

# Regenerate the deposit-audit fixtures with proofs from the pinned deposit key.
dump-deposit-audit-fixtures: check-custom-ring-keys zolana::build-cli
    cargo test -p custom-ring-sdk --features proofs --test deposit_audit_fixtures -- --ignored --nocapture

# === Rings ===

# Create a ring directory, ring.toml and the program keypair.
ring-new *args:
    cargo run -q -p custom-ring-cli -- new {{args}}

# Local validator and services for a ring, ring creation is permissionless.
ring-localnet: check-custom-ring-keys build-programs zolana::build-cli build-ring-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cd zolana && tools/ci/xtask.sh program-ids)"
    bin="zolana/target/debug/zolana"
    workdir="target/ring-localnet"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    export ZOLANA_PHOTON_BIN="$photon_bin"
    export ZOLANA_PROVER_KEYS_DIR="$keys_dir"
    for port in {{localnet-rpc-port}} {{localnet-photon-port}} {{localnet-prover-port}}; do
      lsof -ti "tcp:$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    sleep 2
    accounts_dir="$workdir/accounts"
    (cd zolana && tools/ci/xtask.sh generate-account-snapshots \
      --deploy-dir target/deploy --accounts-dir "$PWD/../$accounts_dir")
    # SIMD-0500 is off, the ring deploys as SBPF v0 like on devnet.
    "$bin" dev start \
      --rpc-port {{localnet-rpc-port}} --photon-port {{localnet-photon-port}} \
      --prover-port {{localnet-prover-port}} \
      --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" zolana/target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" zolana/target/deploy/zolana_user_registry.so \
      -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g
    echo
    echo "localnet ready"
    echo "  rpc       {{localnet-rpc-url}}"
    echo "  photon    {{localnet-photon-url}}"
    echo "  prover    {{localnet-prover-url}}"
    echo "  ring rpc  http://127.0.0.1:{{localnet-ring-rpc-port}}  (started by 'just ring-rpc-derived')"

# Stops the validator, photon, the prover, and a ring RPC left on the ring RPC
# port by a ring's `just pipeline`.
ring-localnet-stop:
    lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    {{stop-localnet-backends}}

# Photon and the prover against an external cluster, Photon indexes from the current slot.
ring-devnet-services rpc_url: check-custom-ring-keys build-prover-server build-ring-photon
    #!/usr/bin/env bash
    set -euo pipefail
    workdir="target/ring-devnet"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1
    nohup "$photon_bin" --rpc-url "{{rpc_url}}" --port {{localnet-photon-port}} --start-slot latest \
      > "$workdir/photon.log" 2>&1 &
    nohup target/prover-server start --keys-dir "$keys_dir" \
      --prover-address 0.0.0.0:{{localnet-prover-port}} --auto-download=true \
      ${ZOLANA_PROVER_REDIS_URL:+--redis-url "$ZOLANA_PROVER_REDIS_URL"} \
      > "$workdir/prover.log" 2>&1 &
    # A slow start must look different from a hang.
    wait_for() {
      printf 'waiting for %-7s %s ' "$1" "$2"
      for _ in $(seq 1 120); do
        if curl -sf --max-time 5 "$3" >/dev/null 2>&1; then
          echo " ready"
          return 0
        fi
        printf '.'
        sleep 1
      done
      echo " timed out"
      echo "$1 did not become ready, see $4" >&2
      return 1
    }
    wait_for photon "{{localnet-photon-url}}" "{{localnet-photon-url}}/readiness" "$workdir/photon.log"
    wait_for prover "{{localnet-prover-url}}" "{{localnet-prover-url}}/health" "$workdir/prover.log"
    echo "devnet services ready"
    echo "  photon    {{localnet-photon-url}}  (indexing {{rpc_url}}, log $workdir/photon.log)"
    echo "  prover    {{localnet-prover-url}}  (log $workdir/prover.log)"

# Stops photon, the prover and a ring RPC started for devnet.
ring-devnet-services-stop:
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true

# Foreground ring RPC in derived mode, one key per ring.
ring-rpc-derived:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/ring-localnet
    secret="target/ring-localnet/root.secret"
    if [ ! -f "$secret" ]; then
        cargo run -q -p zolana-ring-rpc -- keygen --out "$secret" --kind root
    fi
    cargo run -q -p zolana-ring-rpc -- serve --port {{localnet-ring-rpc-port}} \
        --indexer-url {{localnet-photon-url}} --rpc-url {{localnet-rpc-url}} \
        --root-secret-file "$secret"

# === Release and deploy ===

# Release the ring program, ring keys, ring-rpc and zolana-ring, `--upload --prerelease` publishes.
release tag *args: build-programs check-custom-ring-keys
    cargo run -p ring-xtask -- create-release --tag {{tag}} {{args}}

# Build one service image of tools/images.json and publish it by zolana's rules.
publish-image service *args:
    zolana/tools/publish-image.sh {{service}} {{args}}

# Isolated ECS test deployment of the prover and one ring RPC, every resource
# named zolana-rings-test-*, `RINGS_TEST_INDEXER_URL=... just rings-test up`.
rings-test command *args:
    tools/rings-test-deploy.sh {{command}} {{args}}

# Move the zolana pin, `just zolana-bump origin/main`.
zolana-bump rev:
    git -C zolana fetch origin
    git -C zolana checkout --detach {{rev}}
    git add zolana

# === TypeScript ===

# Ring TypeScript SDK formatting, linting, types, unit tests, and package build.
test-ts:
    npm run check:ts

# Ring TypeScript SDK flows against a fresh validator, ring Photon, ring prover and ring RPC.
test-ts-e2e: (_test-ts-live "test:ts:e2e")

# The fresh ring controls suite on the same stack, its runner creates its own mints.
test-ts-ring-controls: (_test-ts-live "test:ts:ring-controls")

_test-ts-live test-script: build-programs build-prover-server zolana::build-cli zolana::ensure-surfpool fetch-custom-ring-keys
    #!/usr/bin/env bash
    set -euo pipefail
    # A command substitution that exits nonzero is no `set -e` trigger, so the
    # ids are captured first and each one the recipe reads is required.
    program_ids="$(cd zolana && tools/ci/xtask.sh program-ids)"
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    : "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"
    : "${DEFAULT_TREE_ADDRESS:?xtask did not emit DEFAULT_TREE_ADDRESS}"
    ring_program_id="{{CUSTOM_RING_PROGRAM_ID}}"
    bin="zolana/target/debug/zolana"
    workdir="target/ts-sdk-e2e"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    }
    trap cleanup EXIT
    rm -rf "$workdir"
    mkdir -p "$workdir/scope"
    export ZOLANA_CONFIG_DIR="$PWD/$workdir"
    # The ring controls suite jumps the surfpool clock only inside a scoped runtime.
    export ZOLANA_PROCESS_SCOPE_DIR="$PWD/$workdir/scope"
    export SURFPOOL_BIN="$PWD/zolana/target/tools/surfpool"
    # Surfpool gives empty slots synthetic hashes, only the fixture keeps ring blocks linked across the jump.
    cargo build --locked -p custom-ring-photon --bin photon --features surfpool-fixture --target-dir target
    export ZOLANA_PHOTON_BIN="$PWD/target/debug/photon"
    export ZOLANA_RING_SURFPOOL_FIXTURE=1
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    export ZOLANA_PROVER_KEYS_DIR="$keys_dir"
    cleanup
    sleep 2

    # The canonical protocol accounts of the current local build, loaded at
    # validator boot, leave ring creation permissionless.
    accounts_dir="$workdir/accounts"
    (cd zolana && tools/ci/xtask.sh generate-account-snapshots \
      --deploy-dir target/deploy --accounts-dir "$PWD/../$accounts_dir")

    ring_dir="$workdir/ring"
    ring_origin="http://localhost:3000"
    ring_rpc_url="http://127.0.0.1:{{localnet-ring-rpc-port}}"
    mkdir -p "$ring_dir"
    solana-keygen new --no-bip39-passphrase --silent --force -o "$ring_dir/authority.json"
    ring_authority="$(solana-keygen pubkey "$ring_dir/authority.json")"

    # The ring program is loaded upgradeable, only its upgrade authority may
    # create the ring config.
    "$bin" dev start \
      --rpc-port {{localnet-rpc-port}} --prover-port {{localnet-prover-port}} \
      --photon-port {{localnet-photon-port}} --account-dir "$accounts_dir" \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" zolana/target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" zolana/target/deploy/zolana_user_registry.so \
      --upgradeable-program "$ring_program_id" target/deploy/custom_ring_program.so \
      "$ring_authority"
    "$bin" config set --rpc-url {{localnet-rpc-url}} \
      --indexer-url {{localnet-photon-url}} --prover-url {{localnet-prover-url}} >/dev/null
    "$bin" wallet new --outfile "$workdir/authority.json"
    mint_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --airdrop-lamports 20000000000 \
      --amount 1000000)"
    mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    test -n "$mint"
    test -n "$token_account"
    token_2022_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --token-program token2022 --amount 1000000)"
    token_2022_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    token_2022_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    test -n "$token_2022_mint"
    test -n "$token_2022_account"

    # The ring CLI parses both targets even though this ring only acts on localnet.
    cat > "$ring_dir/ring.toml" <<TOML
    name = "ts-sdk-e2e-ring"
    program_id = "$ring_program_id"
    authority_keypair = "$PWD/$ring_dir/authority.json"
    target = "localnet"

    [localnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-photon-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"

    [devnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-photon-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"

    # The released rows, the TS suites enrol every party in allow themselves.
    [[policy.rules]]
    subject = "output-owner"
    require = "allow"

    [[policy.rules]]
    subject = "sender"
    require = "allow"

    [[policy.rules]]
    subject = "output-owner"
    forbid = "block"

    [[policy.rules]]
    subject = "sender"
    forbid = "frozen"
    TOML
    cargo run -q -p zolana-ring-rpc -- keygen --out "$ring_dir/auditor.key"
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" \
      init --auditor-pubkey-file "auditor.key.pub"
    # Reads are grant only, the ring authority included.
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" \
      reader grant "$ring_authority"

    # Local mode, the served key is the one the ring config pins.
    cargo build -q -p zolana-ring-rpc --target-dir target
    nohup target/debug/ring-rpc serve --port {{localnet-ring-rpc-port}} \
      --indexer-url {{localnet-photon-url}} --rpc-url {{localnet-rpc-url}} \
      --auditor-key-file "$ring_dir/auditor.key" --ring-program-id "$ring_program_id" \
      --allow-origin "$ring_origin" --webauthn-rp-id localhost \
      > "$workdir/ring-rpc.log" 2>&1 &
    printf 'waiting for ring rpc %s ' "$ring_rpc_url"
    for _ in $(seq 1 60); do
      if curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then break; fi
      printf '.'
      sleep 1
    done
    if ! curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then
      echo " timed out"
      echo "the ring rpc did not answer, see $workdir/ring-rpc.log" >&2
      exit 1
    fi
    echo " ready"
    # The ring-status probe, otherwise exercised only against a hosted rpc.
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" rpc-check

    ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" \
      ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}" \
      ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      ZOLANA_PROVER_URL="{{localnet-prover-url}}" \
      ZOLANA_TREE="$DEFAULT_TREE_ADDRESS" \
      ZOLANA_TEST_MINT="$mint" \
      ZOLANA_TEST_TOKEN_ACCOUNT="$token_account" \
      ZOLANA_TEST_TOKEN_2022_MINT="$token_2022_mint" \
      ZOLANA_TEST_TOKEN_2022_ACCOUNT="$token_2022_account" \
      ZOLANA_CLI_BIN="$PWD/$bin" \
      RING_PROGRAM_ID="$ring_program_id" \
      RING_RPC_URL="$ring_rpc_url" \
      RING_AUTHORITY_KEYPAIR="$PWD/$ring_dir/authority.json" \
      RING_ORIGIN="$ring_origin" \
      RING_PROGRAM_SO="$PWD/target/deploy/custom_ring_program.so" \
      USER_REGISTRY_PROGRAM_SO="$PWD/zolana/target/deploy/zolana_user_registry.so" \
      ZOLANA_TEST_AUTHORITY_WALLET="$PWD/$workdir/authority.json" npm run "{{test-script}}"

# === Formatting and linting ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

check-all:
    cargo check --workspace --all-targets
