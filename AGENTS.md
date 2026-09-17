# AGENTS.md

Context for AI coding assistants working in any repository under
the [STRATO-DAN](https://github.com/STRATO-DAN) organization that doesn't have its own `AGENTS.md`.

## What these repos are

Small, focused, mostly zero-runtime-dependency developer tools, each a standalone npm package
with a `bin/` CLI entry, a `src/` library, and a plain HTML/CSS/vanilla-JS `public/` frontend. No
build step, no framework, no shared codebase between tools.

## House rules

- **Zero runtime dependencies where practical.** Node's standard library covers HTTP servers,
  file I/O, crypto, and subprocess handling for tools this size. Reach for a dependency only when
  there's a real, specific reason the stdlib can't do it — and say what that reason is.
- **Loopback-only by default.** Any local server binds to `127.0.0.1`, never `0.0.0.0`.
- **`execFile`/array-args for any subprocess call, never raw string shell interpolation** — even
  when every interpolated value looks safe today.
- **Honest failure over fabricated success.** A missing dependency, key, or service gets a clear
  error or a documented degraded mode — never a fake result that looks like the real thing.
- **Never leak internal identifiers into a public repo.** This is the one rule with two real
  incidents behind it, not a hypothetical:
  - An early pass across all 5 DAN-OSS tools found internal Linear ticket IDs (`STR-xxx`),
    internal PR numbers, internal codenames, the internal monorepo name, and internal team/lane
    labels baked into shipped source comments and git commit messages — all fixed, but only
    after the fact, via a pre-commit hook scanning staged file content.
  - That fix had its own real gap: the hook only ever scanned staged *file* content, never the
    commit *message* text. An internal ticket ID and an AI-attribution line both slipped into a
    commit message anyway, on a commit whose diff was completely clean — caught only because the
    author happened to reread the message after committing, amended before it was ever pushed,
    then closed the gap for real with a second hook (`commit-msg`) that scans the message itself.
  - Before writing a comment OR a commit message in one of these repos: never reference an
    internal ticket ID, internal PR number, internal codename, an internal monorepo/repo name, or
    an internal team/lane label. Never reference internal infrastructure (IPs, hostnames,
    credential names, internal service URLs). If a design decision genuinely needs explaining,
    explain the *reasoning* in a way a stranger with zero internal context could follow — not a
    pointer to an internal ticket they can't see.
  - **Never add an AI-attribution line to a commit or PR in these repos** (`Co-Authored-By:
    a tool`, "Generated with a coding tool", or similar) — this is a real, standing, deliberately
    enforced rule for this org, not an oversight if it's missing. The `commit-msg` hook blocks
    it the same way it blocks an internal identifier.
- **Test what you change.** If a change is claimed to work, it should have actually been run —
  a syntax check is not a functional test.

## AI-assisted review

Human maintainers may use AI tools to help review contributions to these repos. Please don't
include personal information in your issue, PR, or commit content beyond what's needed to
describe the change.
