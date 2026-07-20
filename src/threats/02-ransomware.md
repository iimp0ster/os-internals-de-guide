# Ransomware: endpoint encryption and control-plane disruption

<div class="threat-sprite-hero" role="note"><img src="../assets/threats/ransomware-pixel.png" alt="" aria-hidden="true"><div><strong>THREAT WALKTHROUGH · RANSOMWARE</strong><span>Anchor on privileged control changes that precede broad data impact.</span></div></div>

<div class="dossier-brief" role="note"><div><strong>EVIDENCE</strong><span class="status-chip source">Akira procedure source-backed</span></div><div><strong>DETECTION</strong><span class="status-chip draft">Windows candidate experimental</span></div><div><strong>NEXT</strong><span><a href="ransomware/01-attack-flow-and-detection.md">attack flow → rules</a></span></div></div>

> **Defender TL;DR:** rapid file modification, recovery-inhibition activity, privilege
> transition, or management-plane commands. **First graph:** [privilege transitions](../privilege-escalation/01-elevation-mechanisms.md).

> **Threat-specific route:** [Akira evidence, attack flow, and detection opportunities](ransomware/01-attack-flow-and-detection.md).

Ransomware is not a Windows-only threat. The outcome is the same, deny access to business
data for extortion, but Windows endpoints, Linux/ESXi infrastructure, and macOS estates
present different operational targets and telemetry paths.

## Applicability at a glance

| OS | State | What changes the investigation |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | **Applicable** | Endpoint execution, credential/privilege use, service and recovery-control changes, and high-rate file activity are the principal investigation path. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | **Applicable** | Linux servers and hypervisors are material targets. On ESXi, management/control-plane actions and VM lifecycle disruption can be more revealing than a desktop-style endpoint chain. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | **Constrained** | Ransomware is possible, but a lower-priority in-the-wild enterprise pattern. Application controls change delivery economics; do not treat low prevalence as an architectural impossibility. |

## Minimal data sources

Start with the control change that precedes impact. File-volume telemetry alone is late.

| OS | Collect | This lets you establish |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | Process creation with command line, plus process-access or recovery-control events | A privileged process is preparing for credential access or recovery inhibition. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux / ESXi | vCenter or ESXi authentication, task, datastore, and VM lifecycle logs | A management-plane sequence can create ransomware impact. Linux endpoint logs are not an ESXi substitute. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | ESF exec and file-modification telemetry | An unsigned or unusual process began broad file impact. This does not prove an Akira branch. |

## The telemetry story

### Windows

```text
initial-access or lateral-movement parent
  → execution and elevation (Sysmon EID 1 / Security 4688; token context where available)
  → service or task changes (SCM / Task Scheduler / registry and file events)
  → broad file modification and recovery-impact actions (file/EDR telemetry)
```

Start with the first anomalous privileged process and its lineage, then determine whether
it creates durable control or begins impact. The existing [elevation](../privilege-escalation/01-elevation-mechanisms.md),
[policy broker](../privilege-escalation/02-polkit-authz.md), [service](../persistence/01-service-daemon.md),
and [executable-memory](../execution/03-in-memory-exec.md) graphs supply reusable cuts.

### Linux and ESXi

```text
remote/admin or compromised-service context
  → privileged command or management-plane action (process / auth / platform management telemetry)
  → service, VM, or storage-state disruption
  → encryption or high-rate modification of target data
```

The Linux chapter library currently provides host-level execution, privilege, and
persistence telemetry. It does **not** yet provide an ESXi control-plane telemetry chapter.
That is a coverage boundary, not a reason to map ESXi activity onto generic Linux auditd.
For a Linux host, correlate the privileged transition with the process and file timeline;
for ESXi, collect and model the relevant hypervisor management-plane events before claiming
coverage.

### macOS

```text
user-approved or untrusted application
  → process execution (ESF NOTIFY_EXEC)
  → file-impact activity (endpoint file telemetry)
  → persistence or privilege attempts where present
```

The macOS branch is constrained by delivery and adoption, not absent by definition. Without
an Endpoint Security-based process collector, the first edge is **Telemetry blind**;
unified logging cannot stand in for reliable exec evidence. Focus on application signer,
lineage, and unusually broad file impact rather than importing Windows-only recovery
artifacts into a macOS hunt.

## Why the paths differ

The target changes the graph. Windows ransomware frequently centers on users and domain
infrastructure; Linux/ESXi ransomware can center on server and virtualization control
planes. macOS has fewer observed enterprise cases and more delivery friction. The common
lesson is to detect the durable privileged and impact edges, then use OS-native telemetry
to establish the sequence.

## Go deeper

- [Elevation mechanisms](../privilege-escalation/01-elevation-mechanisms.md)
- [Policy brokers](../privilege-escalation/02-polkit-authz.md)
- [Service/daemon persistence](../persistence/01-service-daemon.md)
- [In-memory execution](../execution/03-in-memory-exec.md)
- [Threat coverage matrix](../appendix/threat-coverage-matrix.md)
