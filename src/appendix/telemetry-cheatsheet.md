# Telemetry cheat-sheet (Win ↔ Linux ↔ macOS)

A fast lookup mapping "what you want to observe" to the sensor and event on each OS.
Two tiers per OS: the **EDR tier** (richest, Sysmon/ETW, eBPF, ESF) and the **SIEM tier**
(what commonly lands in a log pipeline, Windows event log, auditd, unified log). The gap
between them is where detections quietly fail; each chapter's overlays make that gap concrete.
Events that need explicit enablement are marked *(off by default)* inline, assume nothing is on
out of the box (Sysmon EID 7, 4688 command line, PowerShell SBL 4104, auditd all need configuring).

## Choose an OS telemetry lane

<div class="telemetry-lane-deck" role="list" aria-label="OS telemetry lane primers">
  <div class="telemetry-lane" id="windows-lane" role="listitem"><strong>WINDOWS</strong><span>Begin with Sysmon EID 1 or Security 4688, then add service, task, file, and network context.</span></div>
  <div class="telemetry-lane" id="linux-lane" role="listitem"><strong>LINUX</strong><span>Prefer success-side eBPF exec; auditd needs explicit rules and can lose long arguments.</span></div>
  <div class="telemetry-lane" id="macos-lane" role="listitem"><strong>macOS</strong><span>Use ESF for execution and signing context; Unified Logging is not an exec replacement.</span></div>
</div>

```admonish note
"Sysmon for Linux" deliberately reshapes Linux events into Windows Sysmon EventIDs, so
it doubles as a bridge for a Windows-fluent reader. It is eBPF-backed but exposes a
narrower schema than raw eBPF (Tetragon/Falco), and it has **no ImageLoad (EID 7)**: there is no
library-load probe in Sysmon-for-Linux, so configuring `<ImageLoad>` in its config is a silent
no-op that emits nothing.
```

## Process execution

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: EDR tier | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: SIEM tier | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: EDR tier | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: SIEM tier |
|---|---|---|---|---|---|
| Process created | Sysmon **EID 1**; Security **4688** (cmd line *off by default*, needs the policy); ETW Kernel-Process | eBPF `sched_process_exec`; Tetragon `process_exec`; Sysmon-Linux EID 1 | auditd `SYSCALL`+`EXECVE` (`-S execve,execveat`) *(off by default on Ubuntu/Debian, needs auditd + a rule)* | ESF `ES_EVENT_TYPE_NOTIFY_EXEC` (via `eslogger exec` / Mac Monitor) | unified log, **no clean exec event** |
| Full argv / command line | EID 1 `CommandLine` (single string) | full `argv[]` array | `EXECVE` record `a0..aN` (**can truncate**) | ESF `es_exec_arg` (full) | n/a |
| Parent lineage | EID 1 `ParentImage`/`ParentProcessGuid` | parent pid + exe in event | `ppid` (needs correlation) | ESF parent `audit_token` + path | n/a |
| Fork (no exec) | (N/A on Windows model) | eBPF `sched_process_fork` | auditd `clone`/`fork` | ESF `ES_EVENT_TYPE_NOTIFY_FORK` | n/a |

```admonish tip title="Why sched_process_exec, and what an eBPF 'response' actually is"
The Linux EDR-tier process-created source above is the `sched_process_exec` **tracepoint**,
not a kprobe on `sys_execve`: entry-side execve hooks are TOCTOU-tamperable, miss
`execveat`/`fexecve`, and fire on execs that fail, `sched_process_exec` fires only on
success, kernel-side, across all exec variants. On the *response* side eBPF has two
non-equivalent primitives: `bpf_send_signal()` (5.3) is a **post-hoc** kill delivered on
return to user space (a fork-then-exec can finish first), while a **BPF-LSM** program on
`bprm_check_security` returning `-EPERM` (5.7, and only when `bpf` is in the active `lsm=`
stack) is **synchronous** prevention. See [Methodology → How the Linux EDR tier works](../methodology.md#how-the-linux-edr-tier-works-ebpf).
```

## Code signing / binary identity

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS |
|---|---|---|---|
| Signer identity at exec | separate (Authenticode; not in EID 1) | (ELF has no native signing) | **ESF carries it inline**: team ID, signing ID, cdhash, `is_platform_binary`, code-signing flags |

> macOS ESF is unusually generous here: the *exec event itself* tells you whether the
> binary is an Apple platform binary, who signed it, and its cdhash, context Windows
> makes you stitch together from other sources.

## File activity

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: EDR | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: SIEM | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: EDR | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: SIEM |
|---|---|---|---|---|---|
| File create/write | Sysmon **EID 11** | eBPF (vfs hooks); Tetragon; Sysmon-Linux EID 11 | auditd `PATH` (watch via `-w`); `fanotify` | ESF `NOTIFY_CREATE`/`WRITE`/`CLOSE` | FSEvents (coarse, batched) |
| File rename/delete | Sysmon EID 23/26 | eBPF; auditd | auditd `PATH` | ESF `NOTIFY_RENAME`/`UNLINK` | FSEvents |

## Network

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: EDR | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux: SIEM | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: EDR | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS: SIEM |
|---|---|---|---|---|---|
| Outbound connection | Sysmon **EID 3** | eBPF (kprobe `tcp_connect`); Tetragon; Sysmon-Linux EID 3 | auditd `connect` (noisy); conntrack | ESF `NOTIFY_*` is thin for net → use NetworkExtension content filter | unified log (partial) |

## Module / code loading

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS |
|---|---|---|---|
| Library/image load | Sysmon **EID 7** (ImageLoad) *(off by default, needs explicit `<ImageLoad>` rule)* | eBPF uprobes on `dlopen`; no cheap blanket equivalent; **Sysmon-for-Linux has no EID 7** | ESF `NOTIFY_MMAP` (`+x` mappings) |
| Kernel-mode load | Sysmon EID 6 (driver load) | auditd `init_module`/`finit_module` | ESF `NOTIFY_KEXTLOAD` (kexts deprecated → System Extensions) |

## Identity / privilege

| Observe | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS |
|---|---|---|---|
| Logon | Security **4624/4625** | `journald`/`auth.log` (PAM, sshd); auditd `USER_LOGIN` | ESF `NOTIFY_LOGIN_LOGIN`; unified log |
| Privilege use | 4672/4673; UAC | auditd `sudo`/`USER_CMD`; `/var/log/sudo` | ESF `NOTIFY_SUDO`, `NOTIFY_SU`, `NOTIFY_AUTHENTICATION` |

## The recurring blind spot

The SIEM tier is consistently weaker than the EDR tier, and **macOS is the sharpest
case: the unified log has no reliable process-exec event**, so without an ESF-based
sensor you are effectively blind to execution on macOS. On Linux, `auditd`'s `EXECVE`
argument records can truncate long command lines. Naming the specific gap is the job of
each chapter's section 4, never assert "this is observable" without saying *on which
tier*.
