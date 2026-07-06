# The Cross-OS Detection Graph

**How one threat looks across Windows, Linux, and macOS telemetry — and where each one is blind.**

> Status: **pre-release / work in progress.** An early public cut — the v1 core
> (Execution + Persistence + Privilege Escalation) is drafted; Defense Evasion and
> beyond are stubs. See [`src/appendix/roadmap.md`](src/appendix/roadmap.md).

## The thesis

Every detection engineer is fluent in one OS's telemetry and needs the others. Existing
material is OS-siloed and makes you start from zero, one OS at a time. This guide bridges
from the one thing everyone already shares — **the threat** — and teaches all three OSes
at once by showing how a single behavior casts a *different shadow* in each one's
telemetry.

The model, every chapter:

- **The behavior is an invariant graph** — processes/files/sockets as nodes, exec/open/
  connect/write as edges.
- **The chokepoint is a cut in that graph** — the node/edge every variant must cross (an
  articulation point). You can't obfuscate around a necessary edge; that's why it's the
  detection anchor. ("Detection chokepoint" is a graph-theory term, not a metaphor.)
- **Each OS is an overlay** — the same graph re-labeled with the sensor that observes each
  edge, greyed where none can. A dark node *is* the blind spot.
- **The divergence is the lesson** — the behavior does *not* look the same on every OS.
  Mechanisms differ (macOS `osascript → AppleEvents` has no Win/Linux analog), and a node
  visible on one OS is dark on another. Telemetry, not the threat, dictates what you detect.

It's universal by construction: the spine is the threat, so no OS is privileged and a
Windows, Linux, or macOS expert can all anchor to their own and read the others against it.
It stands on the single-OS prior art (Red Canary's Linux guide, Wardle's *Art of Mac
Malware*, Elastic's Linux Detection Engineering series) and bridges it.

## How each chapter is built

One **behavior** per chapter (technique-cluster grain), grounded in real threats,
following a fixed 8-section template ([`templates/chapter.md`](templates/chapter.md)):

1. the behavior & invariant → 2. threats that use it → 3. the behavioral graph & the cut →
4. per-OS realization & telemetry overlay (the divergence) → 5. visibility delta →
6. detect the cut (per-OS Sigma + the real captured event) → 7. reproduce (Atomic Red Team)
→ 8. false positives & pitfalls.

Methodology, lab build, capture loop, and citation standard:
[`src/methodology.md`](src/methodology.md).

## Build locally

```sh
cargo install mdbook mdbook-mermaid mdbook-admonish mdbook-linkcheck
mdbook-mermaid install .      # one-time: copies theme/mermaid* assets
mdbook-admonish install .     # one-time: copies theme/mdbook-admonish.css
mdbook serve --open           # live preview at http://localhost:3000
```

CI (`.github/workflows/deploy.yml`) builds on every push, fails on broken internal links,
and deploys to GitHub Pages from `main`. Mermaid renders server-side via `mdbook-mermaid`.

## Repository layout

```
src/                 # the book
  introduction.md    # the model
  methodology.md     # lab, capture loop, citation standard
  execution/         # Part I (Slice 0 lives here)
  appendix/          # telemetry cheat-sheet, source canon, roadmap
templates/chapter.md # the 8-section skeleton
labs/                # sensor configs (auditd rules, bpftrace, sysmon, eslogger)
```

## License

TBD at public launch. Intended: prose under Creative Commons; detection rules / lab
configs under a permissive code license (MIT or Apache-2.0). Until then, all rights reserved.
