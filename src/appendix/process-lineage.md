# Process lineage (Linux)

How the OS records "who created this process" — the fork/exec model, where the parent
pointer lives, and the command-line ways to walk it. Referenced by
[process argument masquerading](../defense-evasion/01-process-argument-masquerading.md) (the
PPID/kernel-thread check) and [web shells & anomalous lineage](../persistence/04-web-shells-and-lineage.md)
(the parent→child anomaly the detection is built on).

## 1. fork() then exec() — why lineage exists at all

Linux (like other Unix-likes) never creates a process from nothing. `fork()` duplicates the
calling process — same open file descriptors, same environment, same memory contents (via
copy-on-write) — producing a **child** that is initially a clone of its **parent**. The child
then typically calls one of the `exec()` family to replace its own image with a different
program. That two-step is why lineage is a first-class kernel concept rather than an
afterthought: the kernel already has to track "who forked this" to know where the copied
resources came from, and `exec()` doesn't create a new process — it re-images an existing one,
so the PID and the parent link survive across it.

```admonish note title="Why this matters for detection"
Every process except one has exactly one parent, and that link is set once at `fork()` time
by the kernel — not by anything the child controls. Unlike the argv/comm content discussed in
[process argument masquerading](../defense-evasion/01-process-argument-masquerading.md), a
process cannot rewrite its own PPID after the fact. Lineage is a harder invariant to fake than
identity is.
```

- Every process has **exactly one parent**, tracked from `fork()`.
- The exception: **PID 1** (`init`/`systemd`), started directly by the kernel at boot, has no
  parent, and never exits (if it did, the kernel panics — there's nothing left to reap
  orphans).
- A process with **no parent that isn't PID 1** was `fork()`'d and then **reparented** — its
  original parent exited first, and the kernel reassigns it to PID 1 (or, on modern kernels,
  to the nearest ancestor marked a "subreaper" via `prctl(PR_SET_CHILD_SUBREAPER)`, which is how
  service managers and container runtimes catch their own orphans instead of losing them to
  PID 1). Reparenting itself is a signal worth knowing about: it's exactly what a double-fork
  daemonize sequence produces, and it's also what [T1036.009 Break Process
  Trees](https://attack.mitre.org/techniques/T1036/009/) abuses deliberately — forking twice
  and exiting the intermediate parent severs the lineage an analyst would otherwise walk back
  to the original (often more identifiable) process.
- When a child exits or is killed, the kernel sends `SIGCHLD` to its parent — the mechanism
  process supervisors (`init`, `systemd`, shells with job control) rely on to notice and reap
  it.

## 2. Where the kernel exposes it

| Source | What it gives you | Notes |
|---|---|---|
| `/proc/<pid>/status` → `PPid:` | the parent PID for a single process | one process at a time |
| `/proc/<pid>/task/<tid>/children` | **first-level child PIDs** of a given (thread of a) process | requires `CONFIG_PROC_CHILDREN` (near-universal on modern distros); no recursion — walk it yourself for grandchildren |
| `pgrep -P <ppid>` | child PIDs of `<ppid>` | wraps the `/proc` walk; easiest one-liner |
| `ps -eo ppid,comm` | every process, with its parent PID and command name | best for scanning/grepping the whole tree at once |
| `ps -o ppid= -p <pid>` | the PPID of one process, bare (no header) | scriptable — plug straight into another command |

```sh
# first-level children of PID 1
pgrep -P 1

# the same, read directly from /proc
cat /proc/1/task/1/children

# walk from a known child back to its parent
ps uax | grep sudo | head -n 1
# root       64824  0.0  0.2  13344  4440 pts/1    S    Aug03   0:00 sudo su -
ps -o ppid= -p 64824
#  225864

# scan the whole process table for a given parent-comm relationship
ps -eo ppid,comm | grep sudo
```

None of these are a new mechanism — they're all reading the same `PPid:` field
`/proc/<pid>/status` exposes; `pgrep -P` and the `children` file just save you the walk.

## 3. Why this is the detection anchor for whole classes of behavior

Lineage answers a question identity alone can't: not just "what is this process," but **"is
this the process that's supposed to have spawned it?"** A shell spawned by a web server, a
recon binary (`whoami`, `ifconfig`, `uname`) spawned by a database process, a child that
outlives a parent it was never supposed to survive — none of these require the child process
itself to look suspicious. The anomaly lives entirely in the edge, not the node. See [web
shells & anomalous lineage](../persistence/04-web-shells-and-lineage.md) for the fully worked
example.
