#!/usr/bin/env bash
# Real commit-msg guard — pre-commit.sh only ever saw staged FILE content; a leak (or an AI
# attribution line no commit here should carry) can still ride in through the commit MESSAGE
# itself, a real gap found and closed after it actually happened once during this tool's own
# rebuild. Checks the real message text git is about to use, before the commit is created.
set -euo pipefail

MSG_FILE="$1"

INTERNAL_PATTERN='STR-[0-9]{2,4}|PR #[0-9]+|SKYBIZ|ALPHA dispatch|DAN_LAB_CONSOLE|STRATO_DAN monorepo|Lane: DAN|engine_credentials|100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
AI_SIGNATURE_PATTERN='Co-Authored-By:.*Claude|Generated with \[Claude|🤖 Generated'

hit=$(grep -nEi "$INTERNAL_PATTERN|$AI_SIGNATURE_PATTERN" "$MSG_FILE" || true)
if [ -n "$hit" ]; then
  echo "❌ commit message contains what looks like an internal DAN identifier or an AI-attribution line:"
  echo "$hit" | sed 's/^/    /'
  echo
  echo "Commit blocked. Rewrite the message without it — an internal identifier or an AI" >&2
  echo "signature in a commit message ships permanently the moment this is pushed." >&2
  exit 1
fi

exit 0
