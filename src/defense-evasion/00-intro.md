# Part IV · Defense Evasion

```admonish note title="Sequencing note"
[Roadmap](../appendix/roadmap.md) scopes Defense Evasion as **post-launch** — v1 is
Execution/Persistence/Privilege-Escalation only. This part starts one chapter early as a
standalone stub (process argument masquerading came up out of sequence); treat it as a
pre-v1 draft, not a commitment to ship all of Defense Evasion before launch.
```

Defense evasion is the attacker making their process, file, or action look like something
it isn't — to a human running `ps`, to a SIEM rule keyed on a name, or to an analyst
reading a command line. The common shape: the OS exposes *some* representation of "what
is this process" (a name, an argument list, a signature), that representation is
reconstructed from data the attacker can influence, and influencing it is cheaper than
not being observed at all.

## Chapters

| Chapter | Behavior | OS scope |
|---|---|---|
| [Process argument masquerading](01-process-argument-masquerading.md) | rewrite argv/comm so `ps`/`/proc` show a fabricated identity | Linux (structural — argv lives in user-writable process memory) |

The invariant this part keeps returning to: **whatever telemetry is captured *at* the
privileged transition (the exec syscall) is ground truth; whatever is read back *from* the
process afterward is only as trustworthy as the memory the process controls.**
