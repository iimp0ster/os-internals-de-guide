# Roadmap

The guide is built as a **walking skeleton**: one behavior taken fully end-to-end
first (to prove the lab, toolchain, and chapter template), then replicated. It is
held private until a coherent **v1** ships, then goes public and grows in the open.

Chapter selection is driven by the [cross-OS threat coverage matrix](threat-coverage-matrix.md):
**lead with tri-OS behaviors** (every column populated — the graph model is strongest there),
treat **2-of-3 behaviors** as divergence chapters (the empty/constrained column is the lesson),
and give **1-of-3 behaviors** honest single-OS framing ("no analog elsewhere, and here's why").
The matrix validates Execution and Persistence as strong tri-OS parts; note Privilege Escalation
is more divergent (sudo/UAC/TCC differ sharply) — a good 2-of-3 showcase, though Credential
Access and Discovery are alternative strong tri-OS candidates if v1 scope is revisited.

## v1 (private build → single public launch)

Three parts, ~10 chapters, technique-cluster granularity.

### Part I · Execution
- [x] *(scaffold)* Overview
- [ ] **Script & interpreted execution** — Slice 0 walking skeleton *(draft; capture pending)*
- [ ] Native execution & the loader (ELF + `ld.so` / Mach-O + `dyld` vs PE loader) — *draft; capture pending*
- [ ] In-memory / fileless execution (`memfd_create`+`fexecve`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`) — *draft; capture pending*

**Part I · Execution is fully drafted (3/3 chapters).**

### Part II · Persistence
> Elastic's *Linux Detection Engineering* persistence series is the dominant Linux
> prior art — cite and bridge it; add the Windows and macOS realizations, the cut, and
> the cross-OS telemetry delta, which it lacks.
- [x] **Service & daemon persistence** (systemd vs launchd vs Windows Services/SCM) — *draft; capture pending*
- [x] **Scheduled execution** (cron / `at` / systemd timers vs launchd interval/calendar vs Scheduled Tasks) — *draft; capture pending*
- [x] **Login & shell hooks** (`.bashrc`/`profile.d`/XDG + Login Items vs Run keys/startup; `$PROFILE` tri-OS thread) — *draft; capture pending*
- [ ] *(optional)* "Beyond LaunchAgents" exotics (Fitzl territory)

**Part II · Persistence is fully drafted (3/3 core chapters).**

### Part III · Privilege Escalation
- [x] *(scaffold)* Overview
- [ ] **Elevation mechanisms** — setuid/setgid + sudo/sudoers + capabilities vs UAC / token elevation — *draft; capture pending*
- [ ] **Policy brokers (PolKit / AuthZ)** — PolKit / D-Bus (`pkexec`) vs Authorization Services vs UAC — *draft; capture pending*
- [ ] **TCC & privileged helpers** — macOS TCC + SMJobBless/XPC (1-of-3; no clean analog) — *draft; capture pending*

**Part III · Privilege Escalation is fully drafted (3/3). The entire v1 skeleton is a first draft (9/9 chapters); next gate is the deferred live-capture / emulation phase.**

> Part III throughline: the **observability inversion** of Parts I–II — Linux SIEM (`auth.log`/sudo)
> is usable, macOS sees the authorization act (ESF `NOTIFY_SUDO`/`SU`/`AUTHENTICATION`) but not the
> helper/XPC path, and Windows is the surprising blind spot at the elevation instant (UAC auto-
> elevate/COM bypasses emit no consent event). Research+verify drafting deferred until the full
> Part I–III skeleton exists.

## Post-launch (ship publicly as completed)

Defense Evasion · Credential Access · Discovery · Lateral Movement · C2 / Exfil.

## Deferred — end-of-project

- **Voice pass (do after ALL content is drafted).** Run the `humanizer` skill across the whole
  book to strip AI-writing tells (em-dash overuse, rule-of-three, AI vocabulary, promotional
  phrasing), then rewrite into the author's voice and style. **Requires a real writing sample
  to calibrate** — humanizer removes tells but does not reproduce a personal voice on its own.
  Until then, drafts are content-complete but not yet in-voice.

## Open items (non-blocking)

- **Title** — working title is *"The Cross-OS Detection Graph."* Alternatives:
  *"Provenance: One Threat, Three Telemetries,"* *"Three-OS Detection Engineering."*
  Finalize before public launch.
- **License** — prose under Creative Commons; rules/configs under MIT or Apache-2.0.
  Decide at launch.
- **Cadence** — *assumption:* ~5–8 hrs/week → Slice 0 in ~3–4 weeks, ~1 chapter/week
  after, v1 in ~3–4 months. Drives the calendar only, not the structure.
- **Contributions** — solo through v1; add `CONTRIBUTING.md` + issue templates at launch.
