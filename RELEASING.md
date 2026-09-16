# Releasing

This is the real, shared release process for every small npm package under the
[STRATO-DAN](https://github.com/STRATO-DAN) organization (`dan-oss-commit`, `dan-oss-mock`,
`dan-oss-array`, `dan-oss-recall-dashboard`, `dan-oss-bridge-dashboard`, and any future one built
the same way). Each tool's own README links here instead of repeating it.

## 1. Decide the version bump

These packages follow [semantic versioning](https://semver.org/):

- **patch** (`0.1.0` → `0.1.1`) — a bug fix, no behavior change a user would notice as new.
- **minor** (`0.1.0` → `0.2.0`) — a real new feature, backward compatible.
- **major** (`0.1.0` → `1.0.0`) — a breaking change (a CLI flag removed/renamed, a default
  behavior change, a Node engine bump above what `engines` currently states).

## 2. Bump the version

```bash
npm version patch   # or: minor / major
```

This updates `package.json`'s `version` field and creates a git commit + a git tag
(`vX.Y.Z`) for it automatically — don't hand-edit the version number.

## 3. Push the commit and the tag

```bash
git push origin main --follow-tags
```

## 4. Publish to npm

```bash
npm publish
```

`package.json`'s own `files` field is the publish allowlist — always run
`npm pack --dry-run` first and read the real file list it prints before publishing, to confirm
nothing unexpected would ship (see each repo's own `SECURITY.md`-adjacent discipline on this).

Publishing requires npm auth for the `DAN Systems` npm org/account. Use a short-lived login
(`npm login`) or npm's own [trusted publishing / OIDC](https://docs.npmjs.com/trusted-publishers)
from CI once a release workflow exists — never a long-lived automation token committed anywhere in
a repo or workflow file.

## 5. Create the GitHub release

Create a release on GitHub for the new tag, with real release notes: what changed, any
migration notes for a breaking change, and a thank-you to any external contributor whose PR is
included.

## What this process deliberately doesn't include yet

There is no CI-driven automated release pipeline for these tools yet — every step above is a
real, manual command a maintainer runs locally. That's an honest current limitation, not a design
decision to keep it manual forever; each tool's own README FAQ says so.
