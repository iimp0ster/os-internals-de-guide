# Three-OS behavior taxonomy

[MalAPI](https://malapi.io/) is a useful Windows-oriented seed corpus: it makes a
large API vocabulary searchable by behavior. This page keeps that usefulness, but
normalizes each API into an OS-neutral *behavior*. The result is a translation aid
for detection engineering, not a portability recipe.

It is **not a 1:1 lookup table**. A Win32 API is usually a programming surface; a
Linux syscall, VFS operation, or BPF hook is a kernel boundary; and a macOS
Endpoint Security (ES) event is a supported security event contract. They sit at
different abstraction layers, expose different context, and may prove different
parts of the same story.

## Translation stack and equivalence rules

Use this stack from left to right:

> Windows API or OS facility → behavior → native realization → defender event →
> claim the event supports

The rules keep comparisons honest:

- Start with the objective, such as *create a durable launch point*, not a named
  API. Multiple APIs and utilities can express one objective.
- Name the collection boundary. On Linux that may be a **tracepoint**, syscall
  tracepoint, **VFS/LSM** hook, or **cgroup/socket/tc** network hook—not merely
  “eBPF.” Syscall entry means an action was *attempted*; pair it with a return,
  lifecycle, or state-side event before claiming completion.
- Treat a platform gap as a result. Do not invent a parallel mechanism just to
  fill a column.
- Correlate events into an evidence chain. One event normally establishes a
  narrow fact, not intent or outcome.

The cards below use representative surfaces, not exhaustive inventories. They are
written for defenders; they intentionally omit runnable procedures.

## 1. Process execution

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | `CreateProcess`; shells and service managers can reach the same outcome. | `execve`/`execveat`; libraries and runtimes often wrap them. | `posix_spawn` or `execve`. |
| Native / kernel realization | A new process and primary thread are created. | Successful image replacement reaches the scheduler's process-exec path. | The BSD process image is replaced under XNU. |
| Defender telemetry | Sysmon Event ID 1 or Security 4688; ETW can add process-provider context. | `sched_process_exec` **tracepoint** is success-side; syscall tracepoints show `execve`/`execveat` attempts; a BPF LSM can be an enforcement boundary. | ES `NOTIFY_EXEC` reports the completed execution; `AUTH_EXEC` is the pre-decision authorization event. Exec process metadata includes signing ID, Team ID, CDHash, and code-signing flags. |
| What the event proves | A recorded process start with the available image, command-line, and parent context. | A syscall-entry record proves an attempted exec only. `sched_process_exec` proves a successful exec reached that tracepoint. | A NOTIFY event proves execution was observed after the action; an AUTH event proves a decision was requested, not that it later ran. |
| Blindspot / non-equivalence | Sysmon is a configured sensor, not the `CreateProcess` API itself. | An in-process script or library action need not create another process. | ES event availability varies by macOS version; an ES client needs Apple's Endpoint Security entitlement and is normally delivered as a System Extension. |

Apple's [Endpoint Security overview](https://developer.apple.com/documentation/endpointsecurity)
defines both choices: **AUTH** events let the client authorize a pending action;
**NOTIFY** events report one that has already occurred. That contract is not the
same thing as observing a system call. See also Apple's [`es_process_t`
documentation](https://developer.apple.com/documentation/endpointsecurity/es_process_t),
which describes the exec-time code-signing state.

## 2. File mutation

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | `CreateFile`, `WriteFile`, `MoveFile`, and deletion APIs. | `openat`, `write`, `renameat2`, `unlinkat`, or a runtime's file library. | BSD file APIs; Foundation and other frameworks commonly wrap them. |
| Native / kernel realization | File-system driver and I/O-manager work on an object and handle. | The **VFS** resolves a pathname and dispatches its common file operation to the mounted filesystem; LSM hooks can mediate some operations. | vnode/filesystem operations execute under XNU. |
| Defender telemetry | Sysmon file-create and delete/rename events, plus EDR file telemetry. | VFS/LSM instrumentation gives semantic file context; syscall tracepoints show attempted calls and return values. | ES `NOTIFY_CREATE`, `WRITE`, `RENAME`, `UNLINK`, and related events; corresponding AUTH events can request a decision where supported. |
| What the event proves | The sensor recorded the stated file action, subject to its event definition and configuration. | A syscall entry is an attempt. A VFS completion, return value, or later observed state is needed to say the mutation completed. | A NOTIFY mutation event records the completed operation as exposed by ES. |
| Blindspot / non-equivalence | “File create” may mean created *or overwritten* in a given sensor schema. | A path is not a stable object identity: rename, hard-link, overlay, and mount context matter. VFS semantics are richer than raw syscall names. | FSEvents is coarse and batched; it is not an ES replacement for process-attributed mutation. ES coverage still depends on event type and OS release. |

This is the first place the layer distinction is easiest to see: `WriteFile`,
`write(2)`, and `NOTIFY_WRITE` all concern a write, but they are neither the same
interface nor the same assertion.

## 3. Process survey

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | Tool Help, PSAPI, WMI, and native process-query APIs. | Reading `/proc`, `getdents`/directory traversal, or process-query libraries. | `proc_*`/`sysctl`-style process queries and higher-level tooling. |
| Native / kernel realization | Process-manager objects are queried. | `/proc` presents process state as a virtual filesystem; directory and per-PID file reads realize the survey. | Process information is returned through BSD/XNU query interfaces. |
| Defender telemetry | EDR API telemetry when available; Sysmon process lifecycle is useful context but not a complete “enumeration” event. | VFS hooks or syscall tracepoints on `/proc` directory and file access; LSM can provide policy context. | ES `AUTH_PROC_CHECK`/its notification counterpart, where available, captures a request to inspect process information. |
| What the event proves | A particular API activity only if the collector instruments it. | Reads of `/proc` prove access to particular virtual filesystem objects, not necessarily a full process list. | A process-information check was requested or notified by the ES contract; it does not prove that every process was enumerated. |
| Blindspot / non-equivalence | One tool can use several query paths, and lifecycle logs do not reveal the query. | `/proc` access is noisy and legitimate software reads it often. | The event is a process-check edge, not a generic snapshot of all processes; availability is OS-version dependent. |

## 4. Cross-process control

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | `OpenProcess`, memory APIs, and thread-control APIs are separate calls. | `ptrace`; `process_vm_readv`/`process_vm_writev`; `/proc/<pid>/mem`; signals and debuggers. | Mach task-port acquisition followed by Mach VM or thread operations. |
| Native / kernel realization | A process handle grants requested rights, then later calls read, write, or control the target. | Permission checks and the selected ptrace/process-memory mechanism govern each edge. | Acquiring a task control/read port is distinct from accessing memory or creating a remote thread. |
| Defender telemetry | EDR behavior telemetry; Sysmon EID 8 can record `CreateRemoteThread` where configured. | Syscall tracepoints for `ptrace` and `process_vm_*`; VFS/LSM context for `/proc`; success-side return evidence is essential. | ES `AUTH_GET_TASK` / `AUTH_GET_TASK_READ` cover task-port requests; ES `NOTIFY_REMOTE_THREAD_CREATE` covers a later remote-thread edge. |
| What the event proves | A handle request, memory operation, or remote-thread event proves only that edge. | A successful `process_vm_writev` or `ptrace` operation shows a stronger edge than entry alone, but not a complete execution chain. | A task-port request does **not** prove memory modification or remote execution; a remote-thread event does not reveal every preceding memory action. |
| Blindspot / non-equivalence | Windows APIs can look like a convenient sequence, but telemetry may observe only some links. | There is **no universal Linux `CreateRemoteThread` equivalent**: debugging, memory access, signals, loaders, and language runtimes use distinct paths. | SIP, entitlements, target protections, and ES event availability constrain and shape what is observable. |

The Linux distinction is grounded in the [`ptrace(2)` manual](https://man7.org/linux/man-pages/man2/ptrace.2.html)
and [`process_vm_readv(2)`/`process_vm_writev(2)` manual](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html):
they are different interfaces and permission checks, not aliases for a Windows API.

## 5. Network communication

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | Winsock, WinINet, WinHTTP, and application libraries. | `socket`, `connect`, `send*`, `recv*`, and protocol libraries. | BSD sockets and higher-level networking frameworks. |
| Native / kernel realization | Socket activity traverses the TCP/IP stack; WFP offers filtering layers including application-layer enforcement. | Socket state and packets traverse the network stack. | BSD sockets traverse XNU networking; local IPC can use Unix-domain sockets. |
| Defender telemetry | Sysmon network-connect telemetry; WFP/ALE-aware security products can associate traffic with application identity. | **cgroup/socket** hooks can associate socket operations with workload context; socket-state or **tc** hooks observe other points in the path. Syscall tracepoints give attempted `connect` calls. | ES UIPC events describe Unix-domain socket activity. For general IP networking, use a Network Extension flow/content-filter capability, not ES UIPC events. |
| What the event proves | A connection event proves the sensor's observed connection edge, not application-layer content or an operator's intent. | `connect` entry is an attempted connection; a return value or socket-state evidence is needed for completion. Packet and socket hooks answer different questions. | UIPC proves local Unix-domain IPC, **not generic outbound networking**. Network Extension visibility proves only the flow/content field it exposes. |
| Blindspot / non-equivalence | One API may hide DNS, proxying, redirects, or connection reuse. | Encrypted traffic and connection pooling limit semantic conclusions from kernel network events. | Endpoint Security is not a general IP-flow source; Network Extension is a separate, permissioned platform surface. |

## 6. Durable or recurrent execution (persistence)

| Lens | Windows | Linux | macOS |
|---|---|---|---|
| Representative programming surface | Registry APIs, Service Control Manager APIs, Task Scheduler interfaces, and startup-folder writes. | Unit-file, timer, cron, shell-profile, SSH, and package/configuration writes; service-manager controls. | `launchd` plist and login-item management, plus filesystem/configuration writes. |
| Native / kernel realization | A manager or logon component later consumes stored configuration and starts work. | A manager consumes durable state later; filesystem mutation and future exec are separate observations. | `launchd` or another manager consumes durable state later; the plist write and later launch are separate observations. |
| Defender telemetry | Registry/service/task telemetry plus Sysmon file, registry, and process events. | VFS/LSM file mutations in manager-consumed locations; syscall tracepoints for attempted writes; `sched_process_exec` for later successful execution. | ES file events for launchd/Login Item state plus `NOTIFY_EXEC`/`NOTIFY_FORK` for later activity; signing metadata can enrich the launch. |
| What the event proves | A configuration change or later launch, depending on the event; together they support a stronger persistence claim. | There is **no universal persistence syscall**. Evidence is a durable, manager-consumed state change **plus** later manager-linked execution. | There is likewise no single persistence event; manager-consumed state and later execution must be correlated. |
| Blindspot / non-equivalence | Registry writes are Windows-specific, not a synonym for persistence. | A modified configuration may never be loaded; service-manager telemetry may be separate from kernel telemetry. | A plist-looking file is not inherently a LaunchAgent/Daemon and may be unread or unexecuted; OS/version and entitlement limits still apply. |

## Where the taxonomy expands next

The next cards should preserve the same five lenses while adding behavior families
where the non-equivalence is instructive: module and executable mapping; credential
store access; authentication and token changes; service control; scheduled jobs;
archive/staging; name resolution; removable media; and kernel or extension loading.
Each addition should state the OS-native security boundary first, then ask whether a
common detector claim survives the translation.

## Primary source map

- [MalAPI](https://malapi.io/) is the Windows API seed corpus; Microsoft documents
  [`CreateProcess`](https://learn.microsoft.com/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa),
  [Sysmon event semantics](https://learn.microsoft.com/windows/security/operating-system-security/sysmon/sysmon-events),
  and [Windows Filtering Platform architecture](https://learn.microsoft.com/windows/win32/fwp/windows-filtering-platform-architecture-overview).
- Linux primary references include the kernel's
  [trace-event documentation](https://www.kernel.org/doc/html/latest/trace/events.html),
  [VFS documentation](https://www.kernel.org/doc/html/latest/filesystems/vfs.html), and
  [BPF LSM documentation](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html),
  plus the Linux man-pages for [`execve(2)`](https://man7.org/linux/man-pages/man2/execve.2.html),
  [`process_vm_readv(2)`](https://man7.org/linux/man-pages/man2/process_vm_readv.2.html),
  and [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html).
- Apple documents the [Endpoint Security event types](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t),
  [`es_process_t`](https://developer.apple.com/documentation/endpointsecurity/es_process_t),
  [System Extensions](https://developer.apple.com/system-extensions/), and
  [Network Extension](https://developer.apple.com/documentation/networkextension).
