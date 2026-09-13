# Windows Task Scheduler

<div class="chapter-meta"><div class="attack-techniques"><span class="chapter-meta-label">ATT&amp;CK</span><a class="attack-badge" href="https://attack.mitre.org/techniques/T1053/005/"><span>Scheduled Task</span><code>T1053.005</code></a></div><div class="chapter-meta-details"><span><b>Family</b> <a href="../02-scheduled.md">Scheduled execution</a></span><span><b>Chokepoint</b> task-definition registration</span></div></div>

Windows Task Scheduler is one native implementation of the
[scheduled-execution invariant](../02-scheduled.md): a task definition must be registered
or placed where the scheduler can read it before Task Scheduler can launch its action.

This page goes deeper on Windows. Return to **Scheduled execution** when comparing the same
behavior with Linux `cron` or systemd timers and macOS `launchd` schedules.

## Native object model

<div class="dossier-brief">
  <div><strong>Definition</strong><span>Task XML under <code>System32\Tasks</code></span></div>
  <div><strong>Index</strong><span>Registry <code>TaskCache</code> entries</span></div>
  <div><strong>Broker</strong><span>Task Scheduler service</span></div>
  <div><strong>Action</strong><span>Command launched when a trigger fires</span></div>
</div>

A task can arrive through `schtasks.exe`, the PowerShell `ScheduledTasks` module, the Task
Scheduler COM interfaces, or direct writes to the task files and `TaskCache`. The first
three ask the scheduler to register the task. The last path changes the scheduler-owned
objects directly and can bypass process-name and registration-event assumptions.

```mermaid
flowchart LR
    P["creator process"]:::seen -->|"schtasks / PowerShell / COM"| API["registration interface"]:::seen
    API -->|"writes"| XML[("task XML")]:::seen
    API -->|"indexes"| CACHE[("TaskCache")]:::seen
    P -->|"direct write"| XML
    P -->|"direct write"| CACHE
    S(["Task Scheduler service"]):::seen -->|"reads definition"| XML
    S -->|"trigger fires"| A{{"task action"}}:::seen
    classDef seen fill:#15301f,stroke:#4caf50,color:#dff5e4;
```

## Observable moments

| Moment | Strongest evidence | What it proves | Important limit |
|---|---|---|---|
| creator runs | process creation for `schtasks.exe`, PowerShell, or a registering process | a known registration interface was invoked | direct COM or object writes may not expose a distinctive utility |
| task registered | Task Scheduler Operational 106; Security 4698 when audit policy is enabled | Task Scheduler accepted a task definition | 4698 does not provide every execution detail; direct injection may evade normal registration events |
| definition written | task XML file plus `TaskCache` registry changes | durable scheduler configuration changed | normal administration produces the same object writes |
| action starts | Task Scheduler Operational 200/201 plus process telemetry | a configured action was attempted or launched | the execution parent is scheduler infrastructure, not the original creator |

## Detection layers

Use multiple layers because no single event covers every registration path.

1. **Research:** inventory task creation and modification across the fleet. Retain task name,
   creator, principal, trigger, and action when the collector exposes them.
2. **Hunt:** prioritize tasks whose actions reference user-writable paths, interpreters,
   encoded or inline commands, network retrieval, or unusually frequent triggers.
3. **Analyst:** correlate the registration or object write with the creator lineage and the
   later task action. Treat a missing Event 106 beside direct `TaskCache` changes as useful
   evasion context, not as proof by itself.

```yaml
title: Windows Task Scheduler registration from a high-risk action
status: test
logsource:
  product: windows
  service: taskscheduler
detection:
  registration:
    EventID: 106
  condition: registration
falsepositives:
  - software deployment and maintenance tasks
  - administrative automation
level: medium
# Event 106 establishes registration presence. Join the TaskName to task XML,
# creator-process telemetry, and execution events before judging the action.
```

### Direct TaskCache complement

```yaml
title: Windows TaskCache registry modification
status: test
logsource:
  product: windows
  category: registry_set
detection:
  taskcache_write:
    TargetObject|contains:
      - '\Schedule\TaskCache\Tasks\'
      - '\Schedule\TaskCache\Tree\'
  condition: taskcache_write
falsepositives:
  - Task Scheduler writing its cache during legitimate registration
level: high
# Correlate with the matching task XML and registration events. A direct-write
# hypothesis becomes stronger when TaskCache and XML change without Event 106.
```

## Validated boundaries

The existing lab evidence confirms two complementary routes:

- A normal SYSTEM-context task registration produced process, task-file, and registration
  anchors, including Task Scheduler Operational Event 106.
- A direct `TaskCache` update produced registry and companion task-file evidence without the
  same Event 106 registration anchor.

That distinction is the important lesson: detecting only `schtasks.exe` or only Event 106
does not cover the Windows implementation of scheduled execution.

## Tuning questions

- Is the creator expected to register tasks on this host?
- Does the action resolve to a system-managed path or a user-writable location?
- Is the principal, trigger cadence, or action unusual for the device role?
- Do task XML, `TaskCache`, registration, and execution evidence agree on the same task?
- Did scheduler-owned objects change without the expected registration event?

## Reproduce safely

Use only an authorized, snapshot-bracketed Windows lab. The purpose is to regenerate the
registration, durable-object, and execution evidence—not to run a payload.

```powershell
schtasks /create /tn LabScheduledExecution /tr "cmd.exe /c exit 0" /sc once /st 23:59 /ru SYSTEM
schtasks /delete /tn LabScheduledExecution /f
```

Compare the resulting task name across process creation, Event 106 or 4698 when available,
the task XML, `TaskCache`, and Task Scheduler execution events. Record which evidence is
default-on and which depends on audit policy or an endpoint sensor.

---

[← Scheduled execution comparison](../02-scheduled.md)

<!-- intelopes-source-bound:start:persistence-scheduled-execution-windows -->
## Source-backed variation: Persistence / Scheduled execution (Windows)

<div class="dossier-brief" role="note"><div><strong>EVIDENCE</strong><span class="status-chip source">behavior source-backed</span></div><div><strong>OS</strong><span>windows</span></div><div><strong>MECHANISM</strong><span>`Task Scheduler`</span></div></div>

Using the recovered values, the malware establishes persistence by registering a scheduled task named IntelDriver through the Windows schtasks utility, causing execution upon user logon.

### Evidence and scope

- [From Bing Search to Ransomware: Bumblebee and AdaptixC2 Deliver Akira](https://thedfirreport.com/2026/06/29/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-3) — ice creation. wmiexec.py : Manages WMI remoting. atexec.py : Handles remote scheduled task registration. mmcexec.py : Executes via DCOM. Detailed forensic artifacts and detection strategies for these specific techniques are documented in SnapAt
- [From a Single Click: How Lunar Spider Enabled a Near Two-Month Intrusion](https://thedfirreport.com/2025/09/29/from-a-single-click-how-lunar-spider-enabled-a-near-two-month-intrusion) — They then paused for around five hours. On their return, they deployed a custom .NET backdoor that created a scheduled task for persistence and setup an additional command and control channel. They also dropped another Cobalt Strike beacon that had a new command and control server. They then used a custom tool that used the Zerologon (CVE-2020-1472) vulnerability to attempt additional lateral movement to a second domain controller. After that they then tried to execute Metasploit laterally to that domain contoller via a remote service. However they were unable to establish a command and control channel from this action.
- [Google Doc Sidebar Sends Mac and Windows Users Down Different Paths to Malware](https://www.huntress.com/blog/google-doc-sidebar-malware-mac-windows) — Jon elaborated: "This is also what carries all the persistence for these three modules. It's got a keyboard filter driver, a Windows service, a Win logon, a Run key, a scheduled task to reinstall itself… all that fun junk that we see with these rogue RMM tools being abused."
- [Fake GlobalProtect MSI Targets Myanmar Using Cloudflare and Google Sheets as C2](https://www.malwareinfo.app/blog/posts/fake-globalprotect-msi-targets-myanmar-cloudflare-google-sheets-c2) — Package and host evidence also identified two GlobalProtectVPN RunOnce values—one under HKCU and one under HKLM—and a scheduled task named GlobalProtectVPNUpdate . Microsoft's Run and RunOnce documentation confirms that RunOnce entries request one-time execution at logon. The behaviors align with T1547.001, Registry Run Keys / Startup
- [LATAM Businesses Hit by XWorm via Fake Financial Receipts: Full Campaign Analysis](https://any.run/cybersecurity-blog/xworm-latam-campaign) — Its job is to ensure that the infection survives a reboot by registering a Scheduled Task.
- [The Crypto Wallet That Never Opened: Tampered Exodus Installer Hides a Modular RAT](https://www.huntress.com/blog/exodus-crypto-wallet-installer-rat) — The intrusions didn't look alike at first. On three endpoints, someone opened what they thought was a work-related document, and Windows quietly handed it to the script host instead. In an earlier intrusion on July 24, there was no document at all, just a scheduled task named INetHealth launching conhost.exe --headless powershell -e with a Base64 blob (the infection pre-dated endpoint enrollment and investigation).
- [Beyond the Batch File: Analysis of a Multi‑Stage DonutLoader Infection Chain](https://www.aryaka.com/docs/reports/donutloader-multi-stage-loader-report.pdf) — Using the recovered values, the malware establishes persistence by registering a scheduled task named IntelDriver through the Windows schtasks utility, causing execution upon user logon. As shown in Figure 14, the malware generates an XML-based scheduled task definition and a VBS
- [The Gentlemen Ransomware — Defense Evasion TTPs Uncovered](https://www.huntress.com/blog/the-gentlemen-ransomware-defense-evasion-ttps) — powershell -Command Add-MpPreference -ExclusionProcess C:\\Users\\\[REDACTED\]\\downloads\\G\_hlm7jj\_windows\_amd64.exe -Force powershell -Command Add-MpPreference -ExclusionPath C:\\ -Force The threat actor created Scheduled Tasks that were detected on impacted endpoints, which executed a malicious binary from the temp folder. The binary ( svchost32.exe ), disguised as the legitimate Windows system process svchost.exe , created a SOCKS proxy connection to a command-and-control (C2) IP address at 193.233.202\[.\]17 on port 44729. This Scheduled Task would persist remote access, using malware that would beacon to the C2 IP address:
- [Analyzing Void Dokkaebi’s Cython-Compiled InvisibleFerret Malware](https://www.trendmicro.com/en_us/research/26/e/analyzing-void-dokkaebi-invisibleferret-malware.html) — T1547.001 Boot or Logon AutoStart Execution: Registry Run Key / Startup Folder T1053.005 Scheduled Task/Job: Scheduled Task T1082 System Information Discovery T1083 File and Directory Discovery T1518 Softw
<!-- intelopes-source-bound:end:persistence-scheduled-execution-windows -->
