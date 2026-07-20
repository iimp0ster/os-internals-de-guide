# Source canon

This guide is **empirical-first**: the captured event plus primary documentation are
ground truth; books anchor learning and are cited as "go deeper." Every source below
was verified to exist as of **June 2026** (the as-of date matters, infrastructure and
tooling are time-sensitive).

```admonish warning title="Currency caveat"
The canonical *books* are old (2010-2019). For current kernel and telemetry behavior,
prefer primary docs + your own captures + the actively-maintained blog series. Any
book-sourced *specific* (a version, flag, path, or struct field) is marked `unverified:`
in-chapter until confirmed against the live system.
```

## macOS

| Source | Scope | Access | Notes |
|---|---|---|---|
| Jonathan Levin, *macOS and iOS Internals* Vol I (User Mode) | launchd, XPC, process/thread, frameworks | paid · newosxbook.com | The user-mode bible. |
| Levin, Vol III (Security & Insecurity) | code signing, SIP, AMFI, sandbox, MAC, auditing | paid · newosxbook.com | The detection-relevant volume. |
| Patrick Wardle, *The Art of Mac Malware* Vol 1 (Analysis) | macOS malware analysis | **free** · taomm.org | |
| Wardle, *The Art of Mac Malware* Vol 2 (Detection) | ESF-based detection | **free** · taomm.org · also No Starch (2025) | **Ch 8 = Endpoint Security Framework**, Ch 9 = muting/authorization. Primary ESF detection reference. |
| Csaba Fitzl (theevilbit), *Beyond the good ol' LaunchAgents* | 30+ macOS persistence techniques | free · theevilbit.github.io/beyond | Dominant macOS persistence catalog. |
| Apple Developer, EndpointSecurity framework | ESF event types, structs | free · developer.apple.com | Primary source for ES_EVENT_TYPE_* schemas. |
| Apple Developer, Unified Logging (os_log) | `log stream` / `log show`, predicates | free · developer.apple.com | |
| Objective-See | free macOS security tools + research | free · objective-see.org | OverSight, KnockKnock, etc. |
| Olivia Gallucci, *macOS Internals for Detection Engineers* | launchd, FSEvents, Gatekeeper, code signing | free · oliviagallucci.com | Single-OS prior art, cite + bridge. |

## Linux

| Source | Scope | Access | Notes |
|---|---|---|---|
| Michael Kerrisk, *The Linux Programming Interface* (TLPI) | syscalls, process model, userspace | paid · man7.org/tlpi | 1st ed (2010); still authoritative. |
| Robert Love, *Linux Kernel Development* (3rd ed) | scheduler, mm, process mgmt | paid | Dated to kernel 2.6.34, **conceptual only**; verify specifics vs kernel.org. |
| Brendan Gregg, *BPF Performance Tools* (2019) | eBPF tooling, tracing | paid · brendangregg.com | The eBPF reference; site has free tools. |
| Elastic Security Labs, *Linux Detection Engineering* series (Ruben Groenewoud) | persistence (6 parts), rootkits, containers | free · elastic.co/security-labs | **Dominant Linux persistence prior art.** Cite, do not reproduce. |
| Red Canary, *Detection Engineer's Guide to Linux* | Linux DE methodology, ELF vs PE | free · redcanary.com | Closest existing comparative-to-Windows work (Linux-only). |
| ebpf.io / Cilium Tetragon / Falco docs | eBPF runtime telemetry | free | Current substrate documentation. |
| `auditd` / `audit.rules` man pages, `man7.org` | syscall auditing | free | Primary for auditd record formats. |

## Cross-platform / detection

| Source | Scope | Access |
|---|---|---|
| MITRE ATT&CK, [macOS matrix](https://attack.mitre.org/matrices/enterprise/macos/), [Linux matrix](https://attack.mitre.org/matrices/enterprise/linux/) | technique taxonomy, data sources | free |
| Red Canary Threat Detection Report (Linux/macOS sections) | prevalence, top techniques | free |
| SigmaHQ rules (`rules/linux`, `rules/macos`) | existing detections to reference | free · github.com/SigmaHQ/sigma |
| Atomic Red Team | reproducible behavior tests | free · atomicredteam.io |

## Capture tooling (verified current, June 2026)

- **macOS:** `eslogger` (built-in since macOS 13 Ventura; streams ESF as JSON) ·
  [Red Canary Mac Monitor](https://github.com/Brandon7CC/mac-monitor) (free GUI, Homebrew) ·
  [Crescendo](https://github.com/SuprHackerSteve/Crescendo) (ESF event viewer) ·
  `log stream` / `log show` (unified log, secondary).
- **Linux:** `bpftrace` · [Cilium Tetragon](https://tetragon.io) (CNCF, production) ·
  [Falco](https://falco.org) (CNCF, modern eBPF default) ·
  [Sysmon for Linux](https://github.com/microsoft/SysmonForLinux) (Windows-EventID-shaped, eBPF-backed) ·
  `auditd` + `journald` · `fanotify`.
