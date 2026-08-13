# Process & loader behavior

A process or exec record is bounded evidence. It is not, by itself, proof of authorization, the
full loader or module lifecycle, semantic parent causation, intent, or a later outcome. Use the
[Translation contract](00-translation-contract.md) for the reusable comparison method and evidence
labels; this page applies that contract to executable images and interpreter hand-offs.

| Lens / question | Windows | Linux | macOS |
|---|---|---|---|
| Native start or image mechanism | [CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa) creates a process and primary thread for an executable image; it can return before initialization finishes. | A successful [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) or `execveat` replaces the calling image. A script may hand off through its shebang; an ELF `PT_INTERP` entry orients the dynamic loader. | `posix_spawn` or an exec path starts a Mach-O image; `dyld` is executable-loader context, not proof of a later dylib lifecycle. [Apple documents `posix_spawn`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/posix_spawn.3.html) separately from Endpoint Security. |
| Named collector or control boundary | Configured [Sysmon process creation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) or Security auditing observes a documented process-start record, not the CreateProcess API itself. | Syscall tracing can show an `execve`/`execveat` attempt; a success-side process-exec tracepoint or configured audit/EDR surface has its own semantics and scope. [Kernel trace events](https://www.kernel.org/doc/html/latest/trace/events.html) are collection boundaries, not API aliases. | [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security) has distinct `AUTH_EXEC` and `NOTIFY_EXEC` contracts where the approved, entitled, subscribed client and event are available/configured. |
| What the record supports | A retained process-start observation supports the configured collector's process/image fact. | Syscall entry supports an attempt; successful image replacement needs return/success-side or independently observed execution evidence. | `AUTH_EXEC` supports an authorization request/decision boundary; `NOTIFY_EXEC` supports the documented post-action execution observation. |
| First blind edge | Process creation does not prove initialization, later image/module loading, intent, or outcome. | Image replacement need not create a new child, and an interpreter's internal activity need not create another process event. | An Endpoint Security record is not a generic Unix event and does not establish later behavior or a full module lifecycle. |

> **Analogue verdict.** A configured Windows process-start observation is a useful **closest analogue**
> anchor. Linux attempt-side and success-side observations are **partial analogues** with different
> semantics, not collector parity. macOS has a distinct Endpoint Security AUTH/NOTIFY contract; when
> the necessary client is unavailable, the accurate result may be **no direct equivalent** at that
> collection layer: `Telemetry blind`.

## Evidence ladder

| Claim level | Bounded claim | Platform collection/control gate | Next missing fact |
|---|---|---|---|
| **attempt / request** | A caller asked to start or replace an image; it may fail. | CreateProcess returns failure when it cannot create the process; [`execve`](https://man7.org/linux/man-pages/man2/execve.2.html) returns on error; macOS `AUTH_EXEC` is an [authorization request](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_exec). | A result, post-action notification, or success-side observation. |
| **authorization decision** | A policy decision was requested or rendered at the named control. | Windows and Linux controls must be named by the deployed policy/collector; Apple [Endpoint Security messages](https://developer.apple.com/documentation/endpointsecurity/es_message_t) distinguish authorization from later notification. | A separate observed execution fact; allow does not prove execution. |
| **observed execution / process image** | The named collector observed its documented process/image event. | Configured Sysmon process creation, a Linux success-side surface, or macOS [`NOTIFY_EXEC`](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exec) where available/configured. | Initialization, semantic intent, and later behavior or outcome. |
| **executable-loader boundary** | The native executable image reached its loader context. | Windows initialization remains distinct from request; Linux `PT_INTERP` identifies an ELF interpreter; Mach-O/`dyld` is macOS orientation. [The Linux exec manual](https://man7.org/linux/man-pages/man2/execve.2.html) describes interpreter handling. | Dependency resolution, module lifecycle, and any behavior claim. |
| **outcome corroboration** | A later, separately collected action can bound a stronger timeline. | Use a documented termination, object, network, or state observation with its own collector-health gate; Endpoint Security event coverage varies by the subscribed event. | Intent, maliciousness, and complete causal certainty. |

A loaded executable image or module is not proof of intent or outcome. Dependency resolution,
DLL/shared-object/dylib search and interposition, process-memory module maps, and module-load
analytics are outside this Foundation: see [Native execution & the loader](../execution/02-native-exec-loader.md).
Interpreter forms and any content visibility are owned by
[Script & interpreted execution](../execution/01-script-exec.md).

## Safe conceptual lineages

### Native lineage

| Platform | Benign role and native hand-off | Observation boundary and remaining uncertainty |
|---|---|---|
| Windows | A signed administrative utility is requested by a management parent through CreateProcess. | The request/return is distinct from configured Sysmon process-start evidence; later initialization and image/module observations do not prove the utility completed its management task. |
| Linux | A signed administrative utility reaches successful image replacement through `execve`/`execveat`. | Attempt-side syscall evidence is not success; a success-side process-image observation does not require a new child or establish later utility behavior. |
| macOS | A signed administrative utility enters a `posix_spawn` or exec path for its Mach-O image. | `AUTH_EXEC` is authorization-side and `NOTIFY_EXEC` is observed-execution-side only where the client is available/configured; neither proves later utility actions. |

### Interpreted / hosted lineage

| Platform | Benign role and native hand-off | Observation boundary and remaining uncertainty |
|---|---|---|
| Windows | A locally approved script is evaluated by an interpreter host started through the Windows process-creation path. | The visible host process/image is attributable to the configured process-start record; script content and internal interpreter activity require a separately named collector. |
| Linux | A locally approved script hands off through its shebang to an interpreter, or an already-running interpreter evaluates approved content. | Successful replacement identifies the interpreter image; internal Python/PHP/interpreter activity is not automatically another process event or child. |
| macOS | A locally approved script is evaluated by an interpreter host through a native exec or `posix_spawn` path. | An AUTH/NOTIFY record, where available/configured, concerns the host/image boundary; it does not establish hosted-code semantics or later outcomes. |

**Attribution caveat.** Parent PID, parent image, and timestamp adjacency are correlation pivots,
not proof of causality or provenance. Service managers, wrappers, brokers, process reuse, PID reuse, and
missing collector fields can make the semantic initiator differ from the recorded parent. Require a
stable process identity and time context plus another meaningful edge—such as a documented control,
object action, or success-side record—before writing a causal narrative.

## Evidence Cards

### Windows

1. **Collector** — Configured [Sysmon Event 1](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) or the explicitly configured Security process-auditing surface.
2. **Control / gate** — Sysmon/audit policy must be installed and retain the fields used; CreateProcess return status is a separate request boundary.
3. **What it proves** — The collector recorded its documented process/image observation.
4. **Blind edge** — It does not prove semantic parent causation, completed initialization, module history, or outcome.

### Linux

1. **Collector** — A named syscall, success-side tracepoint, Audit, eBPF, or EDR surface with documented scope.
2. **Control / gate** — The selected rule/program/collector must be active and retain attempt or success context; [Red Hat audit guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening) shows audit records depend on configuration.
3. **What it proves** — An attempt or successful image replacement only as documented by that surface.
4. **Blind edge** — It does not prove a universal predecessor, an interpreter's internal work, later loader state, or outcome.

### macOS

1. **Collector** — An Endpoint Security client subscribed to the applicable AUTH or NOTIFY exec event, where available/configured.
2. **Control / gate** — The client needs the applicable entitlement, approval, subscription, and supported OS/SDK contract; Apple's [client creation documentation](https://developer.apple.com/documentation/endpointsecurity/es_new_client%28_%3A_%3A%29) is the gate reference.
3. **What it proves** — The documented authorization request/decision or post-action process/image observation.
4. **Blind edge** — Absent client/event coverage is `Telemetry blind`; a record does not prove Mach-O loader lifecycle, provenance, intent, or outcome.

These cards deliberately summarize the process/exec question rather than repeat the Foundation
contract. They do not make programming interfaces, collectors, or retained event records a shared
cross-OS schema. Full module lifecycle remains a later native-library phase concern.

## Authorized-lab validation checklist

- **Scope:** Use an authorized isolated lab only. Describe one benign native-management start and
  one locally approved interpreted/hosted start by role, not command.
- **Expected retained shape:** Note OS build and collector/configuration state, then expect only the retained
  process identity, image/interpreter, parent/context, result or action type, time, code-signing
  fields where supplied, and collector-health/loss state.
- **Bounded pass:** Confirm the documented attempt/request, authorization, or observed-execution
  fact at the selected boundary. A process record or allow decision alone is not completion proof.
- **corroboration pass:** Collect a separate, documented observation for any claimed later outcome;
  preserve its distinct gate and semantics.
- **Fail / Telemetry blind:** Stop at the affected claim when the required gate, event, field, or
  health condition is missing.
- **Do not retain:** raw logs, credentials, secrets, executable payloads, capture content, or live infrastructure configuration.

This is `source-backed` only to the extent each cited collector/control is actually present;
otherwise mark the missing evidence `unverified:` or `Telemetry blind`. CI's pinned `mdbook build`
with strict linkcheck remains the render and publication gate.
