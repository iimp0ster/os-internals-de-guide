# Further reading & references

This is a curated reading list for practitioners who want to go deeper. It is not the authority
for a specific claim in the book: use the citation beside that claim and confirm version-sensitive
behavior against the operating system and sensor you actually run.

## Windows

- [Windows Internals](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals) —
  the broadest grounding in processes, memory, I/O, and the Windows security model.
- [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and its
  [event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
  — how a common Windows telemetry layer is configured and what its events represent.
- [Windows Filtering Platform](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page)
  — the native network-filtering and enforcement architecture behind many connection-level
  discussions.

## Linux

- [Linux man-pages](https://man7.org/linux/man-pages/) — the first stop for syscall and ABI
  semantics, including `execve`, `openat`, `connect`, `ptrace`, and audit rules.
- [The Linux Programming Interface](https://www.man7.org/tlpi/index.html) — a durable guide to
  the process, file, IPC, and syscall model. Use kernel documentation for version-specific facts.
- [Linux kernel documentation](https://www.kernel.org/doc/html/latest/) and
  [ebpf.io](https://ebpf.io/what-is-ebpf/) — primary context for kernel trace events, VFS, LSM,
  and eBPF.
- [Cilium Tetragon](https://tetragon.io/docs/) and [Falco](https://falco.org/docs/) — practical
  examples of how runtime-security products express Linux behavior.

## macOS

- [Apple Platform Security](https://support.apple.com/guide/security/welcome/web) — the best
  starting point for macOS trust boundaries, signing, Gatekeeper, SIP, and TCC.
- [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity) and
  [Network Extension](https://developer.apple.com/documentation/networkextension) — primary API
  references for the supported observation and enforcement surfaces.
- [Enleak, *Where Does macOS EDR Telemetry Come From?*](https://enleak.dev/writing/where-does-macos-telemetry-come-from)
  — a credited, live-capture walkthrough that complements this guide's
  [macOS ESF capture lab](macos-esf-capture-lab.md).
- [The Art of Mac Malware](https://taomm.org/) — Patrick Wardle's free, practitioner-oriented
  analysis and detection material.
- [Objective-See](https://objective-see.org/) — research and tools that make macOS persistence,
  execution, and userland telemetry more tangible.

## Cross-OS detection practice

- [MITRE ATT&CK Enterprise matrices](https://attack.mitre.org/matrices/enterprise/) — common
  technique vocabulary; use the Windows, Linux, and macOS views to compare platform coverage.
- [SigmaHQ](https://github.com/SigmaHQ/sigma) — portable detection logic and examples of where
  portability stops at the collector/schema boundary.
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — safe, bounded behavior
  emulation for validating a detection in an authorized lab.
- [Red Canary Threat Detection Report](https://redcanary.com/threat-detection-report/) — useful
  for current practitioner context and telemetry trends; treat prevalence as time-bound.

## A practical reading order

1. Read the relevant Foundation page in this guide and follow its primary citations.
2. Use the OS-native references above to understand the local object, API, syscall, or control.
3. Read the product documentation for the sensor you actually deploy.
4. Use ATT&CK, Sigma, and authorized lab validation to turn the concept into a defensible
   detection—not just a familiar-looking event name.
