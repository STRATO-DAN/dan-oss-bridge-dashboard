#!/usr/bin/env bash
# End-to-end demo for [DAN] BRIDGE DASHBOARD, driven by `make demo`. Reproducible in a throwaway temp
# dir: mint a principal with the `register` subcommand (capture its token + signing key), boot the hub
# on an ephemeral loopback port, sign a message body with the `sign` subcommand, POST it with the
# token, then GET it back. Node standard library + curl only. Cleans up on exit.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
PID=""
cleanup() { if [ -n "$PID" ]; then kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; fi; rm -rf "$TMP"; }
trap cleanup EXIT

export DAN_OSS_BRIDGE_DASHBOARD_DATA="$TMP/data"

echo "== 1. mint a principal (token + signing key are shown once) =="
REG="$(node "$REPO/bin/dan-oss-bridge-dashboard.js" register demo-agent --scope channel:demo)"
TOKEN="$(printf '%s\n' "$REG" | grep -m1 -oE 'X-Bridge-Token: [A-Za-z0-9_-]+' | awk '{print $2}')"
printf '%s\n' "$REG" | grep -m1 -oE '\{[^{}]*"d":[^{}]*\}' > "$TMP/demo-agent.key.jwk"
echo "   principal: demo-agent   scope: channel:demo"
echo "   token captured: ${TOKEN:0:12}...   key file written"
echo

echo "== 2. boot the hub on an ephemeral loopback port =="
DAN_OSS_BRIDGE_DASHBOARD_PORT=0 node "$REPO/bin/dan-oss-bridge-dashboard.js" --json \
  > "$TMP/banner.json" 2> "$TMP/boot.err" &
PID=$!
for _ in $(seq 1 100); do [ -s "$TMP/banner.json" ] && break; sleep 0.1; done
PORT="$(grep -oE '"port":[0-9]+' "$TMP/banner.json" | grep -oE '[0-9]+')"
echo "   hub: $(cat "$TMP/banner.json")"
echo

echo "== 3. sign a message body with the private key (the key never goes to the hub) =="
BODY="$(node "$REPO/bin/dan-oss-bridge-dashboard.js" sign \
  --principal demo-agent --channel demo --text 'hello from make demo' \
  --key-file "$TMP/demo-agent.key.jwk")"
echo "   signed body: $BODY"
echo

echo "== 4. POST it to channel 'demo' with the token =="
curl -s -X POST "http://127.0.0.1:$PORT/api/channels/demo/messages" \
  -H "X-Bridge-Principal: demo-agent" -H "X-Bridge-Token: $TOKEN" \
  -H "content-type: application/json" -d "$BODY"
echo
echo

echo "== 5. read it back =="
curl -s "http://127.0.0.1:$PORT/api/channels/demo/messages?sinceId=0" \
  -H "X-Bridge-Principal: demo-agent" -H "X-Bridge-Token: $TOKEN"
echo
echo
echo "demo complete — temp dir and hub cleaned up."
