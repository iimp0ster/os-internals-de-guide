<!--
CHAPTER TEMPLATE — threat-anchored, graph-represented, divergence-aware.
Copy into src/<part>/<nn>-<slug>.md. One chapter == ONE behavior (technique-cluster
grain), taught through concrete threats and a behavioral graph.

Core model:
  - The BEHAVIOR is the invariant. Draw it once as an OS-neutral graph.
  - The CHOKEPOINT is the cut in that graph — the node/edge every variant must cross.
  - Each OS is a REALIZATION + a telemetry OVERLAY. These DIVERGE: the same threat does
    not look the same on every OS (different mechanisms = different graph shape; different
    sensors = different visibility). Show the divergence; it is the lesson, not a footnote.
  - A node/edge no sensor on that OS can populate is a BLIND SPOT — render it greyed.

Definition of Done is in methodology.md. Mermaid renders server-side via mdbook-mermaid,
so multi-diagram pages are fine. Keep classDef values space-free (e.g. stroke-dasharray:4).
-->

# <Behavior name>

> **ATT&CK:** <T-IDs>  ·  **Tactic:** <tactic>  ·  **Chokepoint:** <the cut, one phrase>  ·  **Status:** draft | captured | reviewed

<!-- One paragraph: what the attacker achieves, and the one-line invariant. -->

## 1. The behavior & invariant

<!-- OS-neutral. What is achieved and why some step is unavoidable. State the invariant
     in one sentence — the thing that holds no matter the OS or the obfuscation. -->

## 2. Threats that use it

<!-- 2-4 concrete, real, cited threats/campaigns that exhibit this behavior. This grounds
     the abstraction. Flag OS-specific threats explicitly (some behaviors are realized
     only on one OS). -->

## 3. The behavioral graph & the cut

<!-- The OS-neutral behavioral graph (mermaid). Identify the chokepoint as the CUT:
     the articulation point / min-cut every variant must traverse. Explain why it's
     necessary (graph-theory framing) — that necessity is why it's the detection anchor. -->

## 4. Per-OS realization & telemetry overlay

<!-- THE HEART OF THE CHAPTER. For each OS: the mechanism (note where the graph SHAPE
     diverges from the others — extra nodes, missing nodes, different edges), the overlay
     with sensor labels, and the blind spots (greyed nodes/edges). Make the divergence
     explicit: "on macOS this branch exists and has no Windows/Linux analog", "this node
     is observable here but dark there."

     SAFEGUARD-PRESSURE NOTE (per OS): why is this behavior hot or cold here? Name the
     safeguard that suppresses/enables it, and when suppressed, where the attacker is
     DISPLACED to (often another chapter). Disambiguate rare = suppressed vs displaced vs
     unobserved. See appendix/safeguard-pressure.md. -->

### Windows
### Linux
### macOS

## 5. Visibility delta

<!-- Symmetric table: rows = graph elements, columns = OS / sensor tier (EDR vs SIEM).
     The deliverable is the named blind spot — what the EDR tier sees that the SIEM tier
     misses, and which OS is blind to which element. -->

## 6. Detect the cut

<!-- Per-OS detections (Sigma) targeting the chokepoint. Below each rule: the REAL
     captured event it fired on (inline). Until captured, mark `unverified:` and stub the
     event with a CAPTURE PENDING admonition. A rule without a real event is not done. -->

## 7. Reproduce it yourself

<!-- Atomic Red Team test IDs + exact manual commands per OS, so a reader regenerates the
     telemetry from a clean lab. Runnable as written. -->

## 8. False positives & pitfalls

<!-- Benign sources of the same graph/signal; tuning notes; what NOT to alert on. -->
