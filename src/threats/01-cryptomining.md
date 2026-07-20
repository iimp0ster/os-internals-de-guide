# Cryptomining: one outcome, three intrusion contexts

<div class="threat-sprite-hero" role="note"><img src="../assets/threats/cryptomining-pixel.png" alt="" aria-hidden="true"><div><strong>THREAT WALKTHROUGH · CRYPTOMINING</strong><span>Anchor on execution that turns into a sustained resource and network workload.</span></div></div>

<div class="dossier-brief" role="note"><div><strong>EVIDENCE</strong><span class="status-chip source">Windows chain source-backed</span></div><div><strong>DETECTION</strong><span class="status-chip draft">candidate correlation</span></div><div><strong>NEXT</strong><span><a href="cryptomining/01-attack-flow-and-detection.md">attack flow → rules</a></span></div></div>

> **Defender TL;DR:** an unusual long-running process, unexpected outbound connections,
> or a web/server process spawning a shell. **First graph:** [web-shell lineage](../persistence/04-web-shells-and-lineage.md).

> **Threat-specific route:** [source evidence, attack flow, and detection opportunities](cryptomining/01-attack-flow-and-detection.md).

Cryptomining is a useful first walkthrough because the desired outcome is stable, consume host
resources for mining, but the path to that outcome changes sharply by OS and deployment
context. Do not hunt for one miner filename. Hunt the chain that acquires execution,
persists it, and produces a sustained resource/network workload.

## Applicability at a glance

| OS | State | What changes the investigation |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | **Applicable** | Commodity delivery and user-executed software are common entry contexts; process, script-host, task, service, and network telemetry form the story. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | **Applicable** | Cloud, container, and internet-facing server compromise are the primary context; a web-server-to-shell lineage is often more diagnostic than the miner process alone. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | **Constrained** | Mining can occur, often through untrusted/pirated software, but it is a lower-priority enterprise pattern. Gatekeeper, notarization, and user-install friction alter delivery; they do not make the outcome impossible. |

## Minimal data sources

CPU use is triage context. Collect the execution and persistence edge first.

| OS | Collect | This lets you establish |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | Process creation with parent/command line, plus service-install events | An installer or updater created a durable execution path. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | eBPF exec or auditd `EXECVE`, plus systemd/cron file or unit changes | A web, container, or scheduled parent created persistence. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | ESF exec with signer, plus LaunchAgent/Daemon file changes | A user-installed path created persistence. This is a hunting model, not GoMiner attribution. |

## The telemetry story

### Windows

```text
user/download or initial-access parent
  → script host or native process creation (Sysmon EID 1 / Security 4688)
  → optional task or service registration (Task Scheduler / SCM + file or registry event)
  → miner process and outbound connection (Sysmon EID 1 + EID 3)
```

Start at the rare parent→child relationship and correlate it with a new persistence
configuration write. Use [interpreter exec](../execution/01-script-exec.md),
[service/daemon persistence](../persistence/01-service-daemon.md), and [scheduled
execution](../persistence/02-scheduled.md) for the durable cuts. A process name or CPU
spike alone is triage context, not proof.

### Linux

```text
internet-facing service
  → unexpected shell/Python child (eBPF exec or auditd EXECVE)
  → fetch or staging activity (eBPF network/file telemetry)
  → unit, timer, or cron configuration write (file event / auditd PATH)
  → restarted process and outbound mining traffic (exec + network telemetry)
```

The high-value pivot is the service-parent lineage: a web server should not normally
spawn a shell, downloader, or compiler. Begin with [web-shell lineage](../persistence/04-web-shells-and-lineage.md), then follow [interpreter exec](../execution/01-script-exec.md)
and the persistence graphs. The EDR tier is important here: auditd can preserve the
creation event but may not retain the full command line or process-to-network join.

### macOS

```text
untrusted application or user-driven install
  → process execution (ESF NOTIFY_EXEC)
  → optional shell/script child (ESF NOTIFY_EXEC)
  → sustained process plus outbound connection (Endpoint Security / network sensor)
```

Treat this as a constrained branch, not an empty one. If ESF is absent, unified logging is
not a reliable replacement for the exec edge; classify that deployment as **Telemetry
blind** for the primary creation evidence. Use signer identity, parent lineage, and
resource/network context together rather than assuming a macOS process name identifies a
miner.

## Why the paths differ

Linux prevalence is tied to server and cloud exposure, while Windows and macOS frequently
begin with user-facing delivery. That is an operational difference, not a claim that only
Linux can mine. The graph library deliberately keeps the shared cuts together while this
walkthrough tells a defender which parent, collector, and persistence surface deserve first
attention on their OS.

## Go deeper

- [Interpreter exec](../execution/01-script-exec.md)
- [Web-shell lineage](../persistence/04-web-shells-and-lineage.md)
- [Service/daemon persistence](../persistence/01-service-daemon.md)
- [Scheduled execution](../persistence/02-scheduled.md)
- [Threat coverage matrix](../appendix/threat-coverage-matrix.md)
