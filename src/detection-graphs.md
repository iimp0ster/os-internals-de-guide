# Detection graph library

These chapters are the reusable internals layer beneath the threat walkthroughs. Each one
defines an OS-neutral behavior, its unavoidable detection cut, and the telemetry overlay
for Windows, Linux, and macOS. Use this index when a signal, not a named threat, is your
starting point.

| I can see… | Start with this graph | Threat walkthroughs that use it |
|---|---|---|
| an interpreter or script host executing | [Interpreter exec](execution/01-script-exec.md) | [Cryptomining](threats/01-cryptomining.md), [Infostealers](threats/03-infostealers.md) |
| browser/interactive parent spawning a shell or LOLBin | [ClickFix attack flow and detection](threats/clickfix/01-execution-and-detection.md) | [ClickFix](threats/05-clickfix.md) |
| a native binary resolving a library from an unusual location | [Loader resolution](execution/02-native-exec-loader.md) | [Infostealers](threats/03-infostealers.md), [Ransomware](threats/02-ransomware.md) |
| anonymous executable memory or a fileless image | [Executable memory](execution/03-in-memory-exec.md) | [Ransomware](threats/02-ransomware.md) |
| a service-manager configuration write | [Service/daemon persistence](persistence/01-service-daemon.md) | [Cryptomining](threats/01-cryptomining.md), [Ransomware](threats/02-ransomware.md) |
| a scheduled-job configuration write | [Scheduled execution](persistence/02-scheduled.md) | [Cryptomining](threats/01-cryptomining.md) |
| a user autostart or shell-hook write | [Login and shell hooks](persistence/03-login-shell-hooks.md) | [Infostealers](threats/03-infostealers.md) |
| a web server spawning an unexpected child | [Web-shell lineage](persistence/04-web-shells-and-lineage.md) | [Cryptomining](threats/01-cryptomining.md) |
| a privilege transition or broker decision | [Elevation mechanisms](privilege-escalation/01-elevation-mechanisms.md) and [policy brokers](privilege-escalation/02-polkit-authz.md) | [Ransomware](threats/02-ransomware.md) |
| a process whose live identity contradicts its creation record | [Process argument masquerading](defense-evasion/01-process-argument-masquerading.md) | [Linux passive backdoors](threats/04-linux-passive-backdoors.md) |

The library remains organized by behavioral graph because one well-defined detection
primitive often serves several threats. A walkthrough gives the primitive context; it does
not duplicate its internals, rules, or validation evidence.
