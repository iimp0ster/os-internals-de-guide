# Threat walkthroughs

A walkthrough starts with a threat, shows its telemetry on each relevant OS, and links to the
reusable detection graphs.

## Applicability contract

Every OS has one state. A blank column is not an answer.

<div class="os-sprite-key" role="list" aria-label="Operating system telemetry key">
  <div class="os-sprite-key-item" role="listitem">
    <img src="../assets/os/windows-pixel-panes.png" alt="" aria-hidden="true">
    <strong>WINDOWS</strong><span>process · service · token</span>
  </div>
  <div class="os-sprite-key-item" role="listitem">
    <img src="../assets/os/linux-pixel-penguin.png" alt="" aria-hidden="true">
    <strong>LINUX</strong><span>exec · unit · BPF</span>
  </div>
  <div class="os-sprite-key-item" role="listitem">
    <img src="../assets/os/macos-pixel-apple.png" alt="" aria-hidden="true">
    <strong>macOS</strong><span>ESF · signer · TCC</span>
  </div>
</div>

| State | Use it when | Required explanation |
|---|---|---|
| **Applicable** | The threat is materially observed or the behavior is normal for that OS. | Name the operating context and the best initial telemetry. |
| **Constrained** | The threat can occur, but safeguards, ecosystem, or attacker economics change the path. | Name the constraint and the displaced or altered path. |
| **No native analogue** | The behavior depends on a subsystem the OS does not implement. | Name the missing subsystem and the nearest, non-equivalent behavior. |
| **Telemetry blind** | The behavior exists, but the stated collection tier cannot observe the needed edge. | Name the blind edge and the collector that would close it, if any. |
| **Unknown** | Evidence is not good enough to claim presence or absence. | State the evidence gap; do not infer safety. |

Applicability describes the threat and mechanism. Visibility describes the sensor. A threat
can apply while the selected telemetry cannot see it.

## Choose a threat walkthrough

<div class="threat-dossier-deck" role="list" aria-label="Threat walkthroughs">
  <a class="threat-dossier-card" role="listitem" href="05-clickfix.html"><img src="../assets/threats/clickfix-pixel.png" alt="" aria-hidden="true"><span><strong>CLICKFIX</strong><span>Browser lure → user-driven execution</span></span></a>
  <a class="threat-dossier-card" role="listitem" href="01-cryptomining.html"><img src="../assets/threats/cryptomining-pixel.png" alt="" aria-hidden="true"><span><strong>CRYPTOMINING</strong><span>Execution → sustained workload</span></span></a>
  <a class="threat-dossier-card" role="listitem" href="02-ransomware.html"><img src="../assets/threats/ransomware-pixel.png" alt="" aria-hidden="true"><span><strong>RANSOMWARE</strong><span>Control disruption → data impact</span></span></a>
  <a class="threat-dossier-card" role="listitem" href="03-infostealers.html"><img src="../assets/threats/infostealers-pixel.png" alt="" aria-hidden="true"><span><strong>INFOSTEALERS</strong><span>User context → reusable secrets</span></span></a>
  <a class="threat-dossier-card" role="listitem" href="04-linux-passive-backdoors.html"><img src="../assets/threats/linux-passive-backdoors-pixel.png" alt="" aria-hidden="true"><span><strong>LINUX PASSIVE BACKDOORS</strong><span>Hidden listener → identity contradiction</span></span></a>
</div>
