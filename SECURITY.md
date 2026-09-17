# Security Policy

## Reporting a vulnerability

If you believe you've found a security vulnerability in any DAN Systems open-source project under
the [STRATO-DAN](https://github.com/STRATO-DAN) organization, please report it privately —
**not** as a public GitHub issue.

**Email: opensource@thedubai.ai**

Please include, if you can:

- Which repository and version/commit is affected.
- A description of the vulnerability and its potential impact.
- Steps to reproduce it, or a proof-of-concept if you have one.
- Any suggested mitigation, if you have one — not required.

You're also welcome to use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
feature (the "Report a vulnerability" button under a repo's **Security** tab), where available, as
an alternative to email.

## What to expect

We'll acknowledge your report and work with you to understand and confirm the issue. We ask that
you give us a reasonable opportunity to investigate and address a report before any public
disclosure, and we'll keep you updated on progress as we work through it.

## Scope

This policy covers the source code in DAN Systems' own public repositories. It does not cover:

- Vulnerabilities in third-party dependencies — please report those to the maintainer of that
  project directly (though we'd still appreciate a heads-up if a DAN-OSS tool bundles or pins an
  affected version).
- Social engineering, physical security, or denial-of-service reports.

## Known limitations (by design)

These are deliberate, documented edges of the current trust model — not regressions. They are recorded
here so operators can reason about them rather than discover them.

- **Public-key enumeration by any authenticated principal.** `GET /api/principals/<id>/pubkey` returns a
  principal's Ed25519 *public* key to any authenticated caller. Public keys are not secret (a receiver
  needs one to verify a message independently of the hub), but this does let one registered principal
  enumerate which principal ids exist and fetch their public keys. There is no unauthenticated access —
  every read stays behind the same auth boundary as the rest of the API — and no private material is ever
  exposed. If principal-id confidentiality matters in your deployment, restrict who you register.

- **PID-reuse edge in the single-writer lock.** A data dir is guarded by `hub.lock`, which stores the
  owning hub's PID. When the lock already exists, a second hub reclaims it only if the recorded PID is no
  longer alive (`kill(pid, 0)`). Operating systems reuse PIDs, so in the narrow window where an unrelated
  process has been assigned the crashed hub's old PID, a stale lock can be misjudged as still-live and a
  legitimate restart is refused (fail-safe: it refuses to start rather than risk two writers). Recovery is
  manual and safe: confirm no hub is running on that data dir, then remove the stale `hub.lock`. The lock
  is a single-writer guard for one machine, not a distributed lock.

## Supported versions

These are small, actively-developed tools without a long-term-support branch model. Please always
test against the latest published release before reporting — older versions may not receive a
fix, and the recommended remediation for any confirmed issue is to upgrade to the latest release.

Thank you for helping keep DAN Systems' open-source projects and their users safe.
