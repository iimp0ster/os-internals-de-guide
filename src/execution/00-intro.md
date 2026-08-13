# Execution graphs

Execution is a foundational graph family. Threat walkthroughs link here when their telemetry
story crosses code execution: the process model and binary format explain which event the
defender can actually observe.

<div class="graph-route" role="note"><strong>THREAT ROUTES</strong><br><span>Return to the outcome: <a href="../threats/05-clickfix.md">ClickFix</a> · <a href="../threats/01-cryptomining.md">Cryptomining</a> · <a href="../threats/03-infostealers.md">Infostealers</a> · <a href="../threats/02-ransomware.md">Ransomware</a>.</span></div>

## Native paths, not one universal execution event

Start with the platform-native boundary. On **Windows**, a [CreateProcess request](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)
creates the process and primary thread, while configured process-start and later image observations
are separate evidence. On **Linux**, [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) or [`execveat`](https://man7.org/linux/man-pages/man2/execveat.2.html) can replace a calling process image
after a successful call; `fork` is one possible predecessor, not a required sequence. On **macOS**,
[`posix_spawn`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/posix_spawn.2.html) or an exec path can start the native image, while [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security) distinguishes a
[pre-action authorization request](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_exec) from a [post-action notification](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exec) where an approved, entitled,
subscribed client is available. Read [Process & loader behavior](../foundations/02-process-and-loader-behavior.md)
before treating any of those records as proof beyond its documented boundary.

## Chapters

| Chapter | Behavior | Example threats |
|---|---|---|
| [Script & interpreted execution](01-script-exec.md) | run code via an interpreter (inline / shebang / piped) | download cradles, macOS osascript stealers, web-shell RCE |
| [Native execution & the loader](02-native-exec-loader.md) | run a compiled binary; the dynamic loader | LOLBins, loader-hijack via `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` |
| [In-memory / fileless execution](03-in-memory-exec.md) | execute without an on-disk image | reflective loaders, `memfd_create` exec, injection |

The invariant that ties the part together: every **native execution path** is bounded evidence.
A request, authorization decision, process/image observation, or later loader record each answers a
different question; the defender must name the sensor and the missing corroboration before forming a
behavior conclusion.
