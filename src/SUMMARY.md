# Summary

[Introduction](introduction.md)
[Start here: begin with a threat](start-here.md)
[Methodology](methodology.md)

# Threat walkthroughs

- [How threat walkthroughs work](threats/00-overview.md)

# ClickFix

- [Overview](threats/05-clickfix.md)
  - [Telemetry & rules](threats/clickfix/01-execution-and-detection.md)

# Cryptomining

- [Overview](threats/01-cryptomining.md)
  - [Telemetry & rules](threats/cryptomining/01-attack-flow-and-detection.md)

# Ransomware

- [Overview](threats/02-ransomware.md)
  - [Telemetry & rules](threats/ransomware/01-attack-flow-and-detection.md)

# Infostealers

- [Overview](threats/03-infostealers.md)
  - [Telemetry & rules](threats/infostealers/01-attack-flow-and-detection.md)

# Linux passive backdoors

- [Overview](threats/04-linux-passive-backdoors.md)
  - [Telemetry & rules](threats/linux-passive-backdoors/01-attack-flow-and-detection.md)

# Detection graph library

- [How to use the graph library](detection-graphs.md)

# Execution graphs

- [Execution: overview](execution/00-intro.md)
- [Script & interpreted execution](execution/01-script-exec.md)
- [Native execution & the loader](execution/02-native-exec-loader.md)
- [In-memory / fileless execution](execution/03-in-memory-exec.md)

# Persistence graphs

- [Persistence: overview](persistence/00-intro.md)
- [Service & daemon persistence](persistence/01-service-daemon.md)
- [Scheduled execution](persistence/02-scheduled.md)
- [Login & shell hooks](persistence/03-login-shell-hooks.md)
- [Web shells & anomalous process lineage](persistence/04-web-shells-and-lineage.md)

# Privilege and access graphs

- [Privilege Escalation: overview](privilege-escalation/00-intro.md)
- [Elevation mechanisms](privilege-escalation/01-elevation-mechanisms.md)
- [Policy brokers (PolKit / Authorization Services)](privilege-escalation/02-polkit-authz.md)
- [TCC & privileged helpers (macOS)](privilege-escalation/03-tcc-helpers.md)

# Defense-evasion graphs

- [Defense Evasion: overview](defense-evasion/00-intro.md)
- [Process argument masquerading](defense-evasion/01-process-argument-masquerading.md)

# Appendix

- [Telemetry cheat-sheet (Win ↔ Linux ↔ macOS)](appendix/telemetry-cheatsheet.md)
- [Process lineage (Linux)](appendix/process-lineage.md)
- [Cross-OS threat coverage matrix](appendix/threat-coverage-matrix.md)
- [Safeguard pressure: why a TTP lands here, not there](appendix/safeguard-pressure.md)
- [Staging & abused locations (Win ↔ Linux ↔ macOS)](appendix/staging-and-abused-paths.md)
- [Source canon](appendix/sources.md)
