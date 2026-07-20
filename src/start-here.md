# Start here: begin with a threat

<div class="os-select-intro">
  <span>PLAYER SELECT</span>
  <h2>Choose your OS telemetry lane</h2>
  <p>Pick the OS you can observe. Each choice opens a fitting threat route and its first useful telemetry story.</p>
</div>

<div class="os-sprite-deck" role="group" aria-label="Cross-OS threat routes">
  <a class="os-sprite-card" href="threats/05-clickfix.md#windows">
    <img src="assets/os/windows-pixel-panes.png" alt="" aria-hidden="true">
    <strong>WINDOWS</strong>
    <span>ClickFix · browser to shell</span>
  </a>
  <a class="os-sprite-card" href="threats/01-cryptomining.md#linux">
    <img src="assets/os/linux-pixel-penguin.png" alt="" aria-hidden="true">
    <strong>LINUX</strong>
    <span>Cryptomining · server to persistence</span>
  </a>
  <a class="os-sprite-card" href="threats/03-infostealers.md#macos">
    <img src="assets/os/macos-pixel-apple.png" alt="" aria-hidden="true">
    <strong>macOS</strong>
    <span>Infostealers · browser to secrets</span>
  </a>
</div>

Want the raw cross-OS telemetry map instead? Open the [telemetry cheat-sheet](appendix/telemetry-cheatsheet.md).

Ask two questions: **what threat am I trying to confirm or rule out, and what should it
leave behind on this OS?** ATT&CK and internals are the supporting library. Use them when
you already know the behavior you need to investigate.

## Choose your starting route

### I have a threat hypothesis

Open a [threat walkthrough](threats/00-overview.md). It shows the OS-specific path and links
to the underlying detection graph.

- **[ClickFix](threats/05-clickfix.md):** browser/clipboard social engineering that
  transitions into Windows, Linux, or macOS native execution.
- **[Cryptomining](threats/01-cryptomining.md):** cloud/server, endpoint, and pirated-app
  intrusion contexts.
- **[Ransomware](threats/02-ransomware.md):** Windows endpoints, Linux/ESXi estates, and
  the constrained macOS column.
- **[Infostealers](threats/03-infostealers.md):** browser/keychain theft versus Linux
  server-secret harvesting.
- **[Linux passive backdoors](threats/04-linux-passive-backdoors.md):** a Linux-specific
  process-identity problem, with explicit non-analogs on Windows and macOS.

### I have telemetry, but no threat hypothesis

Use the [detection graph library](detection-graphs.md). It starts from the edge you can
see, such as interpreter execution, a configuration write, a privilege change, or a
process-lineage break.

### I am planning coverage

Use the [coverage matrix](appendix/threat-coverage-matrix.md) to pick a threat family,
then open its walkthrough.

## How to read a walkthrough

Each walkthrough gives you four things:

1. Whether the threat applies on each OS.
2. The shortest useful telemetry path.
3. What the platform changes or hides.
4. Links to the graph, rule, lab guidance, and sensor limits.

No native analogue means the OS lacks the mechanism. Telemetry blind means the behavior
can occur, but your collector cannot prove it. Treat those as different conclusions.
