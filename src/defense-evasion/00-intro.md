# Defense-evasion graphs

Defense evasion is the attacker making their process, file, or action look like something
it isn't, to a human running `ps`, to a SIEM rule keyed on a name, or to an analyst
reading a command line. The common shape: the OS exposes *some* representation of "what
is this process" (a name, an argument list, a signature), that representation is
reconstructed from data the attacker can influence, and influencing it is cheaper than
not being observed at all.

<div class="graph-route" role="note"><strong>THREAT ROUTE</strong><br><span>Return to the outcome: <a href="../threats/04-linux-passive-backdoors.md">Linux passive backdoors</a>, where a creation-time versus live-identity contradiction is the investigation anchor.</span></div>

## Chapters

| Chapter | Behavior | OS scope |
|---|---|---|
| [Process argument masquerading](01-process-argument-masquerading.md) | rewrite argv/comm so `ps`/`/proc` show a fabricated identity | Linux (structural, argv lives in user-writable process memory) |

The invariant this part keeps returning to: **whatever telemetry is captured *at* the
privileged transition (the exec syscall) is ground truth; whatever is read back *from* the
process afterward is only as trustworthy as the memory the process controls.**
