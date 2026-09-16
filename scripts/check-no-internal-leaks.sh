#!/usr/bin/env bash
# Real pre-commit guard — blocks a commit before it happens, rather than relying on a security
# scrub to catch it afterward and a history rewrite to fix it. Checks the actual staged content
# (git diff --cached), not the working tree, so it can never pass on an already-staged leak.
set -euo pipefail

# Internal identifiers that must never appear in a public DAN-OSS repo: Linear ticket IDs,
# PR numbers, internal codenames/handles, the internal monorepo name, internal lane labels,
# and Tailscale/internal 100.x.x.x addresses.
INTERNAL_PATTERN='STR-[0-9]{2,4}|PR #[0-9]+|SKYBIZ|ALPHA dispatch|DAN_LAB_CONSOLE|STRATO_DAN monorepo|Lane: DAN|engine_credentials|100\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'

# Real secret shapes — defense in depth alongside GitGuardian's own scan, so a leak is caught
# locally before it ever reaches a remote, not only after a push.
SECRET_PATTERN='sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{12,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'

staged_files=$(git diff --cached --name-only --diff-filter=ACM)
if [ -z "$staged_files" ]; then
  exit 0
fi

found=0
while IFS= read -r file; do
  # These scripts' own pattern definitions necessarily contain the literal strings they match —
  # that's a real match on themselves, not a leak. Excluded by path, not by weakening the pattern.
  if [ "$file" = "scripts/check-no-internal-leaks.sh" ] || [ "$file" = "scripts/check-commit-msg.sh" ]; then
    continue
  fi
  # Only text files — skip fonts/binaries, which egrep would otherwise choke on or misreport.
  if ! git diff --cached -- "$file" | grep -qI . 2>/dev/null; then
    continue
  fi
  hit=$(git diff --cached -- "$file" | grep -nEi "$INTERNAL_PATTERN|$SECRET_PATTERN" || true)
  if [ -n "$hit" ]; then
    echo "❌ $file — possible internal reference or secret in staged changes:"
    echo "$hit" | sed 's/^/    /'
    found=1
  fi
done <<< "$staged_files"

if [ "$found" -eq 1 ]; then
  echo
  echo "Commit blocked: staged changes contain what looks like an internal DAN identifier or a" >&2
  echo "real secret pattern. If this is a genuine false positive, fix the underlying wording" >&2
  echo "rather than bypassing this check — a leak here ships permanently once pushed." >&2
  exit 1
fi

exit 0
