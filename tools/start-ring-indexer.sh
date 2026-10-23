#!/usr/bin/env bash
# Starts the ring indexer in the background on a fresh database beside a
# running Photon, and returns once it reaches the confirmed tip.
#
#   tools/start-ring-indexer.sh <workdir> <rpc-url> <photon-url> <port> [start-slot]
#
# RING_INDEXER_BIN names the binary, target/debug/ring-indexer by default.
set -euo pipefail

if [[ $# -lt 4 || $# -gt 5 ]]; then
  echo "usage: $0 <workdir> <rpc-url> <photon-url> <port> [start-slot]" >&2
  exit 2
fi
workdir="$1" rpc_url="$2" photon_url="$3" port="$4" start_slot="${5:-latest}"
bin="${RING_INDEXER_BIN:-target/debug/ring-indexer}"
[[ -x "$bin" ]] || { echo "Missing executable $bin, run just build-ring-indexer" >&2; exit 1; }

mkdir -p "$workdir"
workdir="$(cd "$workdir" && pwd)"
lsof -ti "tcp:$port" -sTCP:LISTEN 2>/dev/null | xargs kill 2>/dev/null || true
for _ in $(seq 1 30); do
  lsof -ti "tcp:$port" -sTCP:LISTEN >/dev/null 2>&1 || break
  sleep 1
done
rm -f "$workdir"/ring-indexer.db "$workdir"/ring-indexer.db-*
nohup "$bin" --db-url "sqlite://$workdir/ring-indexer.db?mode=rwc" \
  --rpc-url "$rpc_url" --photon-url "$photon_url" --port "$port" --start-slot "$start_slot" \
  > "$workdir/ring-indexer.log" 2>&1 &

printf 'waiting for ring indexer http://127.0.0.1:%s ' "$port"
for _ in $(seq 1 120); do
  if curl -sf --max-time 5 "http://127.0.0.1:$port/ready" >/dev/null 2>&1; then
    echo " ready"
    exit 0
  fi
  printf '.'
  sleep 1
done
echo " timed out"
tail -n 50 "$workdir/ring-indexer.log" >&2 || true
exit 1
