# [DAN] BRAND PACK v1 — font licences

All three bundled fonts are **SIL Open Font License 1.1**, which permits redistribution
and bundling, including in commercial products, provided the fonts are not sold on their
own and the licence travels with them.

| font | licence | upstream |
|---|---|---|
| JetBrains Mono | SIL OFL 1.1 | JetBrains |
| Doto | SIL OFL 1.1 | Google Fonts |
| Inter | SIL OFL 1.1 | Rasmus Andersson |

Latin subset only, retrieved 2026-07-24, verified `wOF2` magic on every file.

## 🔴 NOT BUNDLED, AND MUST NEVER BE

**SF Pro / SF Pro Display / SF Mono — Apple.** Licensed for use *on Apple systems*, not for
redistribution. We reference them through the system font stack, where the OS supplies them,
which is free and correct. **Putting an SF Pro file in this folder would be a licence
breach.** Same for Segoe UI (Microsoft) — referenced, never shipped.

The rule generalises: **bundle only OFL/Apache/MIT-licensed faces; reference everything else
through the system stack.** Any new font added here needs its licence checked and recorded
in this table first.
