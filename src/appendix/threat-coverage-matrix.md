# Cross-OS threat coverage matrix

Which threats and behaviors actually occur on which OS, the data that decides what
earns a tri-OS comparative chapter, what is a 2-of-3 (one empty column, itself a
finding), and what is genuinely single-OS.

```admonish note title="Methods & confidence"
Sources: MITRE ATT&CK (platform/technique coverage) plus vendor threat reporting
(Red Canary, Microsoft, SentinelOne, Unit 42, Trend Micro, Halcyon, Elastic, et al.),
as-of **June 2026**. ATT&CK platform mappings are authoritative. **Prevalence ratings
are directional and vendor-reported**, treat the *shape* (which OS, what flavor) as
solid and any single headline statistic as one vendor's measurement, not ground truth.
Behavioral evidence over precise counts.
```

## Threat families × OS

| Threat family | <img class="os-table-icon" src="../assets/os/windows-pixel-panes.png" alt=""> Windows | <img class="os-table-icon" src="../assets/os/linux-pixel-penguin.png" alt=""> Linux | <img class="os-table-icon" src="../assets/os/macos-pixel-apple.png" alt=""> macOS | Shape of the divergence |
|---|---|---|---|---|
| **Infostealers** | High (Lumma, StealC, RedLine, Vidar) | Medium, **different form** | High & fastest-growing (AMOS/Atomic, Poseidon, Cthulhu, Banshee) | Win/macOS = endpoint malware stealing browser/keychain/wallet data; Linux = **server-side credential harvesting** (SSH keys, `/etc/shadow`, `~/.aws`, kubeconfig, env vars) via supply-chain/RATs, not a browser-stealer market |
| **Ransomware** | High (dominant volume) | **High, esp. ESXi/hypervisor** | Low / experimental | NOT Windows-only. Linux/ESXi is a major enterprise category (LockBit 5, Akira, Qilin, BlackBasta, RansomHub, Win+Linux+ESXi variants). ESXi tradecraft attacks the *control plane* (`esxcli`/`vim-cmd` to kill VMs, encrypt VMDKs), a different graph entirely. macOS = NotLockBit (in dev), KeRanger (2016), not real in-the-wild |
| **Cryptominers** | Medium-High (cracked sw, LemonDuck) | **High** (cloud/container/web-exploit; 8220, TeamTNT, Kinsing) | Low (OSAMiner, pirated apps) | NOT Linux-only. Tri-OS; Linux dominates the *cloud/server* context, Windows the *consumer cracked-software* context |
| **RATs / backdoors** | High | Medium | Medium | Genuinely tri-OS. Cross-platform frameworks (Sliver, Mythic) and cross-OS RATs (the 2026 axios-npm RAT shipped Win/Linux/macOS agents; ChillyHell, ZynorRAT). Lazarus ships macOS backdoors |
| **Botnets** | Medium | **High** (IoT/Mirai, web servers) | Rare | ~2-of-3; Linux/IoT dominant, macOS effectively absent |
| **Rootkits** | High (drivers, BYOVD) | High (LKM, eBPF) | **Low, SIP-constrained** | ~2-of-3; macOS kext loading is gated by SIP + notarization, pushing macOS adversaries to userland persistence instead |
| **Supply-chain** | High | High | High | Tri-OS by nature (npm/PyPI/crates are cross-platform); a single malicious package hits all three |

## Behaviors × OS (the chapter-planning view)

Chapters are **behaviors**. This classifies each candidate by how many OS columns it
populates, which sets how strong a tri-OS comparative chapter it makes.

### Tri-OS (all three columns, strongest comparative chapters)

| Behavior | Win | Linux | macOS | Note |
|---|---|---|---|---|
| Script / interpreted execution (T1059) | ✅ | ✅ | ✅ | the walking skeleton |
| Scheduled task/job (T1053) | Task Scheduler | cron / systemd timers | launchd | behavior universal, mechanism diverges |
| Service / daemon persistence (T1543) | Services/SCM | systemd | launchd daemons/agents | |
| OS credential access (T1003) | LSASS/SAM/NTDS | `/etc/shadow` | Keychain | **behavior** universal; stores totally different |
| Account / file discovery (T1087/T1083) | ✅ | ✅ | ✅ | commands differ, behavior identical |
| Application-layer C2 + exfil (T1071/T1041) | ✅ | ✅ | ✅ | protocol-independent |
| Masquerading (T1036) | ✅ | ✅ | ✅ | |
| Boot/logon autostart (T1547) | Run keys | XDG / init | LaunchAgents | tri-OS *goal*, mechanisms 1-of-3 each |

### 2-of-3 (one column empty or constrained, divergence is the lesson)

| Behavior | Win | Linux | macOS | Note |
|---|---|---|---|---|
| Remote-service lateral movement (T1021) | RDP/SMB/WinRM/DCOM | SSH | SSH | only **SSH** is shared; the rest are Windows-only |
| Process injection (T1055) | rich (DLL inject, hollowing) | ptrace / LD_PRELOAD | task_for_pid (SIP-limited) | diverges sharply; macOS most constrained |
| Kernel rootkits (T1014) | drivers | LKM / eBPF | ✗ SIP-blocked | macOS column is the finding |

### 1-of-3 (single-OS, frame honestly as "no analog elsewhere")

- **Windows-only:** registry Run keys (T1547.001), LSASS dumping (T1003.001), DCOM/WMI/WinRM (T1021.003/T1047/T1021.006), DLL search-order hijack (T1574.001).
- **macOS-only:** TCC bypass (T1548.006), AppleEvents/`osascript` inter-app scripting, `DYLD_INSERT_LIBRARIES` dylib hijack, plist/Login Items.
- **Linux-only:** LKM/eBPF rootkits (T1547.006), `LD_PRELOAD` / `ld.so.preload` (T1574.006), XDG autostart (T1547.013).

## Myth-busting (lead-with content)

```admonish bug title="Two corrections worth a callout in the guide"
- **"Ransomware is Windows-only."** False. Linux/ESXi ransomware is a major enterprise
  category, by 2025 ESXi accounted for a large and rising share of incidents, and every
  top RaaS ships a Linux/ESXi locker. macOS is the only marginal column.
- **"Cryptominers are Linux-only."** False. Tri-OS. Linux dominates the cloud/server
  context (most compromised cloud assets mine Monero), but Windows (cracked software) and
  macOS (pirated apps) both have active miners.
```

## How to use this matrix

Use it to set the investigation boundary before copying a detection across platforms:

- A tri-OS behavior can share one objective while still needing three OS-native rules.
- A constrained or empty OS column is evidence. Do not fill it with a superficial equivalent.
- The [safeguard-pressure guide](safeguard-pressure.md) explains why a behavior is common,
  constrained, or difficult to observe on a given platform.
