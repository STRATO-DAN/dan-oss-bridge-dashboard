# Contributing

Thanks for considering a contribution to a DAN Systems open-source project. This file applies to
every repo under the [STRATO-DAN](https://github.com/STRATO-DAN) organization that doesn't have
its own `CONTRIBUTING.md`.

## Before you file an issue

- Search existing open and closed issues first — your question or bug may already be answered.
- If it's a bug, include: what you ran, what you expected, what actually happened, and your OS +
  Node.js version (`node --version`). A minimal repro (a few commands, or a tiny script) is worth
  more than a long description.
- If it's a feature request, describe the real problem it solves, not just the feature itself —
  it's easier to evaluate "I need X because Y" than a solution proposed in isolation.
- Security issues do **not** go in a public issue — see `SECURITY.md`.

## Submitting a pull request

1. Fork the repo and create a branch off `main` with a short, descriptive name
   (`fix-listen-port-parsing`, not `patch-1`).
2. Keep the change focused. A PR that fixes one bug or adds one small feature is easy to review
   and merge; a PR that also reformats unrelated files or adds unrelated cleanup is not.
3. If the repo has tests, add or update them for your change and confirm they pass locally before
   opening the PR. If it doesn't have tests yet, a short manual verification note in the PR
   description (what you ran, what you saw) is still expected.
4. Write a clear PR description: what changed, why, and how you verified it.
5. Be responsive to review feedback — a PR that goes quiet for a long time may be closed and can
   always be reopened once it's picked back up.

## Coding standards

These are deliberately small, focused tools. Unless a specific repo's own README says otherwise:

- **Zero runtime dependencies where practical.** Several DAN-OSS tools ship with none at all —
  Node's own standard library covers HTTP servers, file I/O, crypto, and subprocess handling for
  a tool this size. If you think a dependency is genuinely needed, say why in the PR description;
  it'll get real consideration, but the bar is high.
- **Plain HTML/CSS/vanilla JS on the frontend**, no build step, no framework — a contributor
  should be able to read `public/app.js` top to bottom without knowing a specific tool's own
  conventions.
- **Loopback-only by default.** Any local server binds to `127.0.0.1`, never `0.0.0.0`, unless a
  change is specifically about making that configurable — and if so, it needs to be opt-in and
  clearly documented, not a silent default change.
- **Subprocess calls use `execFile`/array-args, never raw string shell interpolation** — even when
  every interpolated value looks safe today, the array form removes the question entirely for
  whoever reads it next.
- **Honest failure over fabricated success.** If a dependency, key, or service is missing, say so
  plainly (a clear error, a documented degraded mode) — never silently substitute a fake result
  that looks like the real thing.

## License

By contributing, you agree your contribution is licensed under the same license as the repo
you're contributing to (see that repo's own `LICENSE` file — code is MIT across all DAN-OSS
tools). The "DAN" name and logo are trademarked separately and are not covered by the MIT grant —
see each repo's own `TRADEMARK.md`.
