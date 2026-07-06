# Safeguard pressure: why a TTP lands here, not there

The coverage matrix says *whether* a TTP appears on each OS. This explains *why* — and
the answer is almost always the OS's safeguards (or their absence). A safeguard's default
state is a **prior on TTP prevalence**: harden an edge and attackers either stop using it,
get rerouted, or keep using it where the safeguard isn't deployed.

```admonish note title="Methods & confidence"
Sources: vendor security docs (Microsoft, Apple, Broadcom, Red Hat, Ubuntu) + threat
reporting, as-of **mid-2026**. **Safeguard defaults are version- and edition-specific** —
treat "default-on since version X" as vendor-documented as-of this snapshot, and re-check
for the build in front of you. Behavioral direction is solid; exact percentages are
vendor-reported.
```

## Four mechanisms

| Mechanism | Definition | One-line example |
|---|---|---|
| **Suppression** | safeguard makes the TTP rare/infeasible | macOS SIP + Apple-Silicon kext death → kernel rootkits ~extinct on default Macs |
| **Enablement** | absence/permissive default makes the TTP common | Linux `LD_PRELOAD` has no default guard → routine rootkit persistence |
| **Displacement** | safeguard doesn't kill the *goal*, it reroutes to a different TTP | macOS Gatekeeper → attackers pivot to ClickFix (`curl \| osascript` pasted in Terminal) |
| **Observation bias** | TTP is feasible but under-*observed* because no sensor is deployed | Linux `auditd` off by default → LKM/eBPF rootkits happen but are invisible |

```admonish danger title="The detection-engineering rule this forces"
"Rare on this OS" is never a finished thought. Disambiguate it into **suppressed**
(genuinely doesn't happen), **displaced** (the goal moved to a different TTP — go detect
*that*), or **unobserved** (it happens and you're blind — a telemetry problem, not a
threat-absence). Conflating these is how coverage maps lie.
```

## Windows — heavily defaulted-on; attacks displaced up the stack

| Safeguard | Default (as-of mid-2026) | Suppresses | Displaces attackers to |
|---|---|---|---|
| Credential Guard + LSA Protection | on — Win11 22H2+ Enterprise/Edu, domain-joined, eligible HW | LSASS dumping (T1003.001) — Mimikatz "mostly useless" | DCSync (T1003.006), Kerberoasting, token theft, MFA-phishing, cloud secret-manager APIs |
| AMSI + Script Block Logging + PowerShell v2 removal | AMSI on; SBL on Win11 22H2+; v2 removed 24H2/Server 2025 | noisy PowerShell obfuscation | LOLBins (MSBuild, T1218), JS/VBScript, in-process C# runspaces, AMSI bypass |
| HVCI + vulnerable-driver blocklist; cross-signed trust removed (Apr 2026) | on — Win11 22H2+ eligible HW | BYOVD kernel rootkits (T1543.003 driver-via-service + T1014 rootkit) | zero-day kernel exploits, usermode persistence (Run keys, COM hijack) |
| ASR rules | **off by default** (deploy via MDM/GPO) | Office child-process chains *when enabled* | direct-executable delivery, LOLBins in unmanaged estates |

Net: the noisy, well-instrumented Windows TTPs are declining where defaults are on; the
action moves to **identity-layer** attacks and **living-off-the-land**. Note ASR is the
counter-example — a strong control that is *off* by default, so its TTPs persist widely.

## macOS — unsigned-code and kernel paths shut; attacks pushed to userland + the user

| Safeguard | Default (as-of mid-2026) | Suppresses | Displaces attackers to |
|---|---|---|---|
| SIP + Apple-Silicon kext death → System Extensions | on; 3rd-party kexts need Reduced Security (non-default) | kernel rootkits, system-file tamper | userland LaunchAgent persistence; **infostealers (~65% of new macOS malware)** |
| Hardened Runtime + Library Validation | on for App Store + platform binaries | `DYLD_INSERT_LIBRARIES` on signed binaries (T1574.006) | injection into old/unsigned apps; `osascript`; notarized malware |
| Gatekeeper + notarization + quarantine | on | running unsigned/un-notarized downloads | **ClickFix** (`curl \| osascript` pasted in Terminal — fileless, no quarantine); cracked apps that `xattr -d com.apple.quarantine`; signed+notarized droppers (MacSync, Dec 2025) |
| TCC | on | silent access to files/automation/AppleEvents | TCC-bypass CVEs; social-engineering the consent prompt |

Net: because the unsigned-binary and kernel routes are so well suppressed, macOS adversaries
converge on **the user** (ClickFix consent, fake password dialogs via `osascript`) and
**user-readable data** (keychain, browser, SSH keys). The walking-skeleton chapter's
`osascript`/ClickFix focus is a direct consequence of this displacement.

## Linux — defaults are permissive or off; enablement + a structural visibility gap

| Safeguard | Typical default | Suppresses / Enables | Note |
|---|---|---|---|
| Module signing + Secure Boot + lockdown | **off unless Secure Boot enabled** (often not, on servers) | enables LKM rootkits (T1547.006) where absent | suppressed only on hardened hosts |
| SELinux (RHEL enforcing) vs AppArmor (Ubuntu) | enforced on RHEL/Fedora; ~44% of estate doesn't enforce | gates priv-esc / `LD_PRELOAD` *when enforcing* | adoption splits by distro |
| Yama `ptrace_scope` | 0/1 | constrains ptrace injection | bypassed by 2025 seccomp-notify / io_uring injection |
| `unprivileged_bpf_disabled` | **2 (disabled)** Ubuntu 21.10+/SUSE/RHEL | suppresses *unprivileged* eBPF | **privileged** eBPF rootkits viable post-root (BPFDoor: 151 samples in 2025; Symbiote) |
| `LD_PRELOAD` / `/etc/ld.so.preload` | **no default safeguard** | enables library-injection persistence | SELinux-enforcing can gate it; rarely does |

## ESXi — the worst case: easy and blind

`execInstalledOnly`, lockdown mode, and Secure Boot are **all off by default**, the VIB
acceptance policy is permissive, and there is **no native EDR** on the hypervisor. SSH/shell
are off by default (the one good default), but post-exploitation re-enables them. Result:
ESXi is **both highly targeted and poorly observed** — which is exactly why Linux/ESXi
ransomware (Akira et al.) scaled so fast. This is enablement *and* observation bias stacked.

## Observation bias — the trap, called out

```admonish bug title="\"It happens, we just can't see it\" — distinct from \"it doesn't happen\""
- **Linux `auditd` is off by default** on Ubuntu/Debian/Fedora (much of cloud Linux). LKM/eBPF
  rootkits, `LD_PRELOAD`, and ptrace injection then occur with **no sensor present** — absence
  of telemetry, not detection evasion.
- **eBPF rootkits filter the eBPF tools watching them** — a structural blindness no amount of
  rule-writing fixes.
- **ESXi has no native EDR** and sparse default logging.

For each, "low prevalence on Linux/ESXi" in any dataset may be a *measurement artifact*. Say
so in the chapter; never let an empty cell imply safety.
```

## What this means for the guide

Each chapter's per-OS overlay (section 4) carries a **safeguard-pressure note**: why this
behavior's edge is hot or cold on this OS, and — when a safeguard suppresses it — **where the
attacker is displaced to** (often another chapter). This turns the guide from a static map
into a causal one: the reader learns not just "what's observable" but "why this is the threat
you actually see here, and what to watch when the obvious path is closed."
