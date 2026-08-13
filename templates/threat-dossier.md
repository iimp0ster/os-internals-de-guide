<!--
THREAT WALKTHROUGH TEMPLATE, the primary, defender-facing entry point.

A walkthrough starts from a threat outcome or a well-defined threat family. It DOES NOT
duplicate the behavior/graph chapters. It assembles them into an OS-specific investigation
story and links back to durable detection opportunities, rules, and validation evidence.

Every OS must have a state: Applicable, Constrained, No native analogue, Telemetry blind,
or Unknown. Never leave an OS blank. Distinguish absence of the mechanism from absence of
telemetry.
-->

# <Threat outcome or family>

<div class="dossier-brief" role="note">
  <div><strong>EVIDENCE</strong><span class="status-chip source">source-backed / scoped</span></div>
  <div><strong>DETECTION</strong><span class="status-chip draft">validation state</span></div>
  <div><strong>NEXT</strong><span>attack flow → telemetry → rule</span></div>
</div>

> **Defender TL;DR:** <symptom / first pivot>. **First graph:** <link>.

## Applicability at a glance

| OS | State | What changes the investigation / why not applicable |
|---|---|---|
| Windows | Applicable / … | |
| Linux | Applicable / … | |
| macOS | Applicable / … | |

## Minimal data sources

Start with the smallest source set that can support the stated detection. Add enrichment
only when it changes the decision.

| OS | Collect | This lets you establish |
|---|---|---|
| Windows | <minimum event/source and required fields> | <defensible claim> |
| Linux | <minimum event/source and required fields> | <defensible claim, or explicit gap> |
| macOS | <minimum event/source and required fields> | <defensible claim, or explicit gap> |

## The telemetry story

### Windows
<!-- chain: action → named collector/event → next pivot -->

### Linux
<!-- chain: action → named collector/event → next pivot -->

### macOS
<!-- chain, or explicit no-native-analogue / telemetry-blind explanation -->

## Defanged procedure excerpt

Keep the execution order, tool names, flags, parent-child relationship, and artifacts that
explain the detection. Replace hosts, tokens, hashes, passwords, payload bytes, and runnable
output paths with placeholders. State when the report does not publish a payload.

```text
<parent or delivery step>
  -> <defanged execution or procedure>
  -> <observable artifact or child>
```

**Rule mapping:** <which retained fields or sequence the rule uses>.

## Why the paths differ
<!-- safeguards, ecosystem, architecture, or operational context; do not infer safety -->

## Go deeper
<!-- links to the reusable graph chapters and coverage matrix -->
