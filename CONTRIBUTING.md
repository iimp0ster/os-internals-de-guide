# Contributing

Thanks for considering a contribution. This project bridges Windows, Linux, and macOS
detection engineering by anchoring every chapter to a threat, not an OS — see
[`README.md`](README.md) for the thesis and [`src/introduction.md`](src/introduction.md)
for the full model. This file covers how to actually send work in.

Read [`src/methodology.md`](src/methodology.md) before your first PR — it defines the lab,
the capture loop, and the citation standard everything below assumes. Skimming one drafted
chapter (e.g. [`src/persistence/01-service-daemon.md`](src/persistence/01-service-daemon.md))
is also worth the five minutes; it shows the standard in practice, not just in the abstract.

## Ways to contribute

Ordered lightest to heaviest. Pick whichever matches the access and time you have — you do
not need a full three-OS lab to send something useful.

### 1. Fixes & polish (no lab needed)

Typos, broken links, unclear prose, a mermaid diagram that doesn't render, an appendix entry
that's stale (`src/appendix/telemetry-cheatsheet.md`, `threat-coverage-matrix.md`,
`staging-and-abused-paths.md`, `sources.md`). Just open a PR directly — no issue needed for
anything this small.

### 2. Detection improvements (light lab)

Tightening or adding a Sigma rule for a chokepoint a chapter already identifies (its
section 6). Every rule still has to clear the validation bar in `methodology.md`: fired on a
real captured event, and confirmed *not* to fire on a benign baseline. If you can write the
rule logic but can't yet produce a live capture, open a draft PR, prefix the claim
`unverified:`, and say so in the PR description — that's an accepted, honest starting point,
not a blocker.

### 3. Single-OS or partial chapter contributions

The macOS lab has a hard prerequisite most contributors won't have: real Apple hardware with
Endpoint Security Framework entitlements (see `methodology.md`). Rather than let that gate
contributions entirely, it's fine to:

- send just the Windows and/or Linux realization + telemetry overlay of a chapter, or
- fill in only the macOS section of an existing chapter if that's the access you have.

Mark whatever you couldn't personally capture as `unverified:`, open the PR as a draft, and
name the gap explicitly in the description (e.g. "macOS §4/§6 pending — needs Apple hardware,
help wanted"). Someone else can pick up the missing piece later; you don't have to own all
three OSes to contribute a chapter.

### 4. New chapters (full lab, full template)

A complete chapter following [`templates/chapter.md`](templates/chapter.md), meeting all
seven Definition of Done criteria in `methodology.md` (all 8 sections present, the cut
identified, divergence and blind spots made explicit, a visibility-delta table, per-OS Sigma
validated against a real event, a runnable Atomic Red Team repro, sourced claims).

**Open an issue first**, naming the behavior/technique, before drafting. That avoids two
people writing the same chapter, and lets a maintainer check it against
[`appendix/roadmap.md`](src/appendix/roadmap.md) and the
[cross-OS threat coverage matrix](src/appendix/threat-coverage-matrix.md) — tri-OS behaviors
(every column populated) are prioritized first; 2-of-3 behaviors make good divergence
chapters; genuinely single-OS behaviors get honest single-OS framing.

## The one rule that matters most

This project's credibility rests on the empirical-first, cited standard in
`methodology.md`. In practice:

- Every factual claim names a **source** and an **as-of date**.
- Anything you didn't personally confirm on a live system — a field name, an event ID, a
  Sigma rule that hasn't fired — gets prefixed `unverified:`. This isn't a failure state,
  it's how partial-lab contributions stay honest. Don't present something inferred from a
  man page or blog post as confirmed.

## Setting up

`methodology.md` covers the lab in full (Linux: auditd + eBPF + Sysmon-for-Linux + journald,
all on one VM; macOS: ESF via `eslogger`, **real Apple hardware required**; Windows: Sysmon +
ETW). Check the macOS requirement before you plan a contribution around it — it's easier to
scope your PR to what you have going in than to discover the gap halfway through.

To build the book locally:

```sh
cargo install mdbook mdbook-mermaid mdbook-admonish mdbook-linkcheck
mdbook-mermaid install .      # one-time
mdbook-admonish install .     # one-time
mdbook serve --open           # live preview at http://localhost:3000
```

Run `mdbook build` (with linkcheck) before opening a PR — CI fails the same way on a broken
internal link, so catching it locally first saves a round trip.

## Workflow

1. Fork the repo and branch off `main`. Branch names aren't enforced, but
   `<part>/<slug>` (e.g. `persistence/web-shells`) or `fix/<slug>` for small fixes keeps
   things readable.
2. New chapters go in `src/<part>/<nn>-<slug>.md`, numbered to match the existing sequence
   in that part; add the corresponding entry to `src/SUMMARY.md` yourself.
3. Respect data hygiene: raw captures (full event dumps, pcaps, EVTX) never get committed —
   only the curated, redacted excerpts that ship inline in a chapter. No hostnames,
   usernames, internal IPs, or tokens, ever. `.gitignore` catches the obvious cases; redaction
   past that is a manual discipline — check your own diff before pushing.
4. In the PR description, state plainly which of the seven Definition of Done items
   (`methodology.md`) are met and which are intentionally deferred (e.g. "macOS pending").
   Reviewers can't tell the difference between "forgot" and "known gap" unless you say so.

## Style notes

- Match the density already in the book — no filler, no marketing language. `README.md` and
  `src/introduction.md` are the reference for tone.
- Keep mermaid `classDef` values space-free (e.g. `stroke-dasharray:4`) — an
  `mdbook-mermaid` parsing quirk, also flagged in `templates/chapter.md`.
- Don't over-polish voice on a first draft. A project-wide pass to unify style happens later,
  once all content exists (see "Deferred" in `src/appendix/roadmap.md`). Write clearly and
  correctly; let the later pass handle consistency.

## Proposing a chapter or reporting a gap

Open an issue. Reference `src/appendix/roadmap.md` (what's planned) and
`src/appendix/threat-coverage-matrix.md` (what earns a chapter and why) so the discussion
starts from the same backlog the maintainer is already using.

## License

TBD at public launch (see `README.md`) — intended as Creative Commons for prose and a
permissive license (MIT or Apache-2.0) for detection rules and lab configs. By contributing,
you agree your work may be released under whichever of those the project ultimately adopts.
