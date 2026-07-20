# ClickFix: one social-engineering invariant, three OS telemetry stories

<div class="threat-sprite-hero" role="note"><img src="../assets/threats/clickfix-pixel.png" alt="" aria-hidden="true"><div><strong>THREAT WALKTHROUGH · CLICKFIX</strong><span>Anchor on the browser/clipboard boundary that becomes user-driven native execution.</span></div></div>

<div class="dossier-brief" role="note"><div><strong>EVIDENCE</strong><span class="status-chip source">behavior source-backed</span></div><div><strong>DETECTION</strong><span class="status-chip draft">experimental · unverified</span></div><div><strong>NEXT</strong><span><a href="clickfix/01-execution-and-detection.md">attack flow → rules</a></span></div></div>

> **Defender TL;DR:** a browser-based verification/error lure followed by an interactive
> shell, script host, or LOLBin. **Next page:** [ClickFix execution: attack flow,
> telemetry, and detection](clickfix/01-execution-and-detection.md).

ClickFix is an unusually good cross-OS walkthrough because the attacker cannot reach execution
without persuading the user to cross a visible boundary: copy the supplied text, open an
OS-native execution surface, and run it. The exact command, payload, and lure can rotate;
the **browser/clipboard → user-driven execution** transition remains the investigation
anchor.

## Applicability at a glance

| OS | State | What changes the investigation |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | **Applicable** | The common user path is browser/clipboard → Run dialog or shell → `mshta`, `cmd`, or PowerShell. The process tree and command-line telemetry are the first durable endpoint evidence. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | **Applicable** | The user is directed from the browser into a terminal or launcher, which creates a shell/process execution event. Desktop Linux is the relevant context; server-only Linux estates have a much smaller user-driven surface. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | **Applicable** | The user is directed to Terminal, then pastes a shell command. ESF `NOTIFY_EXEC`, signer identity, and the Terminal-to-shell lineage are the key endpoint evidence. |

## Minimal data sources

Start with process execution that retains parent and command-line context. Browser and
network data help, but they are not required to detect the endpoint transition.

| OS | Collect | This lets you establish |
|---|---|---|
| <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | Sysmon EID 1, or Security 4688 with command line and parent context | An interactive shell or `mshta` branch began after user action. |
| <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | eBPF exec, or auditd `EXECVE` with parent/process correlation | A launcher or terminal started the shell chain. Auditd can truncate long wrappers. |
| <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | ESF `NOTIFY_EXEC` with parent, argv, and signer | Terminal started an unusual shell or decoder path. Unified Logging alone cannot prove this. |

## The telemetry story

### Windows

```text
spoofed page in browser
  → browser writes a command to the clipboard (browser/proxy evidence, often not endpoint telemetry)
  → user opens Run or a shell
  → explorer.exe or interactive shell starts a script host / LOLBin (Sysmon EID 1 or Security 4688)
  → remote retrieval or child execution (Sysmon EID 3 + process lineage)
```

The high-value cut is the unusual interactive parent→child edge. Hunt.io's reported
campaign used a government-themed lure and a clipboard-delivered `mshta` execution path;
the attribution to APT36 is assessed as medium confidence, so this is a **ClickFix
behavioral** walkthrough, not an attribution detection. A browser process spawning a shell is
often high signal; an `explorer.exe` child needs command line, user session, and surrounding
lure context before it is actionable.

### Linux

```text
spoofed page in browser
  → clipboard write (browser telemetry, if collected)
  → user opens a launcher or terminal
  → shell execution (eBPF exec / auditd EXECVE / Sysmon for Linux process creation)
  → downloader, script, or child process (process + network telemetry)
```

Hunt.io observed a Linux-specific CAPTCHA flow which instructed the user to paste a copied
shell command through the desktop launcher. The reported payload did not yet show follow-on
malicious activity, which is an important validation boundary: detect the user-driven shell
execution and retain the timeline, but do not claim persistence or C2 from that sample.
The shell's parent and full argv are more useful than the lure text; auditd may lose detail
on long command lines, making the EDR tier the preferred source for this cut.

### macOS

```text
spoofed page in browser
  → clipboard write (browser telemetry, if collected)
  → user opens Terminal
  → zsh/bash execution (ESF NOTIFY_EXEC)
  → network retrieval, script execution, and optional cleanup (endpoint process/file/network telemetry)
```

The macOS column is supported by a separate DriveSurge ClickFix campaign, not by the
Windows/Linux Hunt.io campaign. Silent Push reported a fake reCAPTCHA flow that profiled for
desktop macOS, replaced the clipboard with a shell command, and instructed the user to paste
it into Terminal. If Endpoint Security telemetry is absent, the critical Terminal-to-shell
edge is **Telemetry blind**; Unified Logging is not a reliable substitute for exec evidence.

## Why this is a real tri-OS lesson

The invariant is social rather than kernel-level: the user completes the execution bridge.
What changes is the native execution surface and the evidence it produces, Run-dialog/LOLBin
lineage on Windows, launcher/terminal shell execution on Linux, and Terminal plus ESF/signer
context on macOS. Do not call the technique Windows-only because a particular campaign has
only Windows and Linux branches, and do not merge separate campaigns into a single actor
attribution merely to fill the macOS column.

## Evidence and scope

- Hunt.io documented the government-themed campaign's Windows and Linux branches, and
  assessed its APT36 alignment at medium confidence (published 2025-05-05):
  [APT36-style ClickFix campaign](https://hunt.io/blog/apt36-clickfix-campaign-indian-ministry-of-defence).
- Silent Push documented the separate DriveSurge macOS ClickFix flow (published 2026-05-30):
  [DriveSurge ClickFix analysis](https://www.silentpush.com/blog/drivesurge/).

## Investigate and go deeper

1. [ClickFix execution: attack flow, telemetry, and detection](clickfix/01-execution-and-detection.md)
   keeps the OS-specific attack flow, telemetry, Sigma examples, sources, and collection
   caveats together.
2. [Interpreter exec](../execution/01-script-exec.md) explains the reusable process-exec
   graph after the ClickFix branch is established.

- [Native execution and the loader](../execution/02-native-exec-loader.md)
- [Telemetry cheat-sheet](../appendix/telemetry-cheatsheet.md)
- [Threat coverage matrix](../appendix/threat-coverage-matrix.md)
