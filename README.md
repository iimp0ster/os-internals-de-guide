# The Cross-OS Detection Graph

**Start with a threat. See what it leaves behind on Windows, Linux, and macOS.**

[Read the guide](https://iimp0ster.github.io/os-internals-de-guide/)

> Status: public work in progress. The current release includes five threat walkthroughs
> and reusable detection graphs for execution, persistence, privilege and access, and
> one defense-evasion behavior.

## Start here

Use the route that matches the evidence you have:

- **I have a threat hypothesis:** open a [threat walkthrough](src/threats/00-overview.md).
- **I have telemetry but no hypothesis:** use the [detection graph library](src/detection-graphs.md).
- **I am planning coverage:** use the [cross-OS coverage matrix](src/appendix/threat-coverage-matrix.md).

The guide does not treat an empty OS column as safety. Each walkthrough labels a platform as
Applicable, Constrained, No native analogue, Telemetry blind, or Unknown and explains why.

## What is in the guide

### Threat walkthroughs

The walkthroughs put behavior in context before sending you to the lower-level graph:

| Threat | Starting point |
|---|---|
| ClickFix | Browser or clipboard social engineering that becomes native execution. |
| Cryptomining | Workload abuse, persistence, and server or endpoint access paths. |
| Ransomware | Impact paths across Windows endpoints, Linux or ESXi estates, and constrained macOS cases. |
| Infostealers | Browser and credential access, including Linux server-secret collection. |
| Linux passive backdoors | Hidden listeners and process-identity contradictions. |

### Detection graph library

The graph library is the reusable internals layer. It starts from the edge you can see:

- **Execution:** interpreter activity, native loader behavior, and executable memory.
- **Persistence:** service or daemon changes, scheduled work, login hooks, and web-shell lineage.
- **Privilege and access:** elevation mechanisms, policy brokers, TCC, and privileged helpers.
- **Defense evasion:** process-argument masquerading.

Each graph identifies the behavior that must happen, the detection chokepoint, the matching
telemetry on each OS, sensor limits, detection logic, and expected false positives.

## What a walkthrough gives you

- An OS-specific applicability decision with the reason behind it.
- A short telemetry path from threat behavior to rule match.
- The minimal data sources that can prove the behavior.
- Defanged procedures or payload fragments where they explain what the rule is targeting.
- Curated emulation event excerpts where the rule has been validated.

The point is to make the comparison useful in an investigation. A Windows, Linux, or macOS
specialist can begin with the OS they know, then see what changes on the others.

## Build locally

```sh
cargo install mdbook mdbook-mermaid mdbook-admonish mdbook-linkcheck
mdbook-mermaid install .      # one-time: copies theme and Mermaid assets
mdbook-admonish install .     # one-time: copies admonish assets
mdbook serve --open           # live preview at http://localhost:3000
```

GitHub Actions builds each pull request and deploys the book to GitHub Pages from `main`.

## Repository layout

```
src/
  start-here.md             # defender-first entry routes
  threats/                  # threat walkthroughs and OS applicability decisions
  detection-graphs.md       # signal-first graph index
  execution/                # reusable execution graphs
  persistence/              # reusable persistence graphs
  privilege-escalation/     # reusable privilege and access graphs
  defense-evasion/          # reusable defense-evasion graphs
  appendix/                 # coverage matrix, cheatsheets, and source canon
templates/chapter.md        # detection graph skeleton
labs/                       # sensor configurations and lab material
```

## License

TBD at public launch. Intended: prose under Creative Commons; detection rules and lab
configs under a permissive code license (MIT or Apache-2.0). Until then, all rights reserved.
