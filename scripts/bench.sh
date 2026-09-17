#!/usr/bin/env bash
# Throughput benchmark for [DAN] BRIDGE DASHBOARD, driven by `make bench`. Mints a principal, boots the
# hub on an ephemeral loopback port, then hands off to scripts/bench.mjs which posts N signed messages
# and reads them back, timing each direction. Node standard library only. Cleans up on exit.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
N="${BENCH_N:-100}"
TMP="$(mktemp -d)"
PID=""
cleanup() { if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT

export DAN_OSS_BRIDGE_DASHBOARD_DATA="$TMP/data"

REG="$(node "$REPO/bin/dan-oss-bridge-dashboard.js" register bench-agent --scope channel:bench)"
TOKEN="$(printf '%s\n' "$REG" | grep -m1 -oE 'X-Bridge-Token: [A-Za-z0-9_-]+' | awk '{print $2}')"
printf '%s\n' "$REG" | grep -m1 -oE '\{[^{}]*"d":[^{}]*\}' > "$TMP/bench-agent.key.jwk"

DAN_OSS_BRIDGE_DASHBOARD_PORT=0 node "$REPO/bin/dan-oss-bridge-dashboard.js" --json \
  > "$TMP/banner.json" 2> "$TMP/boot.err" &
PID=$!
for _ in $(seq 1 100); do [ -s "$TMP/banner.json" ] && break; sleep 0.1; done
PORT="$(grep -oE '"port":[0-9]+' "$TMP/banner.json" | grep -oE '[0-9]+')"

echo "== bench: $N messages over loopback (127.0.0.1:$PORT), channel 'bench' =="
REPO="$REPO" TOKEN="$TOKEN" PORT="$PORT" KEY_FILE="$TMP/bench-agent.key.jwk" N="$N" \
  node "$REPO/scripts/bench.mjs"
echo "reproduce: make bench"
