# Network & connection behavior

Filesystem answers where an artifact lands. Process and loader behavior answers how code starts.
Network behavior answers which remote or local peer that code tries to reach, or which service it
offers. Those are different evidence questions: a socket request, a permitted flow, a listening
service, and bytes exchanged are not interchangeable claims.

This page concerns the connection boundary. DNS, TLS, HTTP, and payload content are later
protocol-layer questions. A remote connection is neither proof of malicious intent nor proof that
an application-level transaction succeeded.

## Start with the connection question, not the familiar event

| Lens / question | Windows | Linux | macOS |
|---|---|---|---|
| Shared objective | Did a process initiate a remote connection, or did a service receive one? | Did a process create a communication endpoint, connect it to a peer, or expose a listener? | Did an application create a network flow to a peer, or expose a network-facing service? |
| Native boundary | [Windows Filtering Platform (WFP)](https://learn.microsoft.com/en-us/windows/win32/fwp/about-windows-filtering-platform) filters network data across stack layers. A connection record is an observation at a selected WFP/Sysmon boundary, not a Winsock API trace. | [`socket(2)`](https://man7.org/linux/man-pages/man2/socket.2.html) creates a communication endpoint; [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html) asks it to connect to an address. A listener has separate [`bind(2)`](https://man7.org/linux/man-pages/man2/bind.2.html) and [`listen(2)`](https://man7.org/linux/man-pages/man2/listen.2.html) boundaries. | A deployed [Network Extension content filter](https://developer.apple.com/documentation/networkextension/content-filter-providers) can receive application network flows. Endpoint Security's `UIPC_CONNECT` events apply only to UNIX-domain sockets, not general TCP or UDP connections. |
| Named collector or control | Configured [Sysmon Network Connect (EID 3)](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) records process-initiated TCP/UDP connections. Where the audit subcategory is enabled, [WFP Event 5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) records a connection WFP permitted. | A Linux Audit rule scoped to `connect` can observe that syscall where configured; a separately named eBPF/EDR sensor has its own hook, kernel, namespace, and deployment contract. Do not treat either as a universal Linux network event. | A configured [Network Extension filter data provider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider) receives `NEFilterFlow` objects for connections opened by applications. The provider and its approval/deployment are collection gates; it is not an Endpoint Security subscription. |
| Collection gate | Sysmon EID 3 is disabled by default because of volume; WFP auditing is a separate audit-policy decision. | The collector must be present, enabled, and scoped to the workload, namespace, ABI, and event boundary that matter. The exact eBPF/EDR product or audit rule must be named. | The content-filter provider must be deployed and configured. A flow can carry source-app/process identity fields, but the available fields and policy depend on the provider and OS contract. |
| Bounded proof / non-proof | EID 3 proves its documented process-initiated TCP/UDP connection observation. Event 5156 proves WFP permitted the recorded connection. Neither alone proves DNS intent, application protocol, transferred content, or maliciousness. | A `connect` observation proves only the selected syscall boundary and retained fields. For nonblocking sockets, `EINPROGRESS` is not successful establishment; completion needs a later check or separate documented observation. | A filter flow proves that the deployed provider saw its documented flow. Endpoint Security `UIPC_CONNECT` is useful for local IPC, but it is **no direct equivalent** to a general TCP/UDP connection record. |
| Analogue verdict | A useful reference implementation, not the required starting point. | Usually a **partial analogue** until the host role and named sensor are known. | A Network Extension flow can be a **closest** or **partial analogue**; an Endpoint Security-only estate can be `Telemetry blind` for the general remote-connection question. |

The table is deliberately bidirectional. Start with whichever operating system you know; translate
the behavior and evidence boundary, not `Sysmon EID 3`, `connect`, or a product event name.

## Connection proof ladder

| Claim level | What it means | What it still does not establish |
|---|---|---|
| **endpoint created** | A process created a socket or equivalent communication endpoint. | That the endpoint contacted a peer. |
| **connection requested** | A process asked the OS to associate an endpoint with a peer. | That policy allowed it, the peer responded, or application data moved. |
| **connection permitted / observed** | The selected collector recorded its own allowed or initiated-flow semantics. | DNS intent, TLS/HTTP semantics, transferred bytes, and malicious intent. |
| **listener exposed** | A service bound and began accepting work, or a later inbound flow reached it. | That every inbound connection was malicious or that the process owns the expected service role. |
| **protocol or content behavior** | A separate, documented sensor supplied name, protocol, or content context. | That the entire session was captured or that its content was malicious. |

> **Why this matters for interpreter tradecraft.** A PHP, Python, Perl, Go, or other runtime can
> create a network connection in-process. The connection boundary remains observable only where
> a sensor captures it; it does not reveal the source code, function call, or user-controlled
> request that caused it. Process lineage and script-content visibility are separate evidence
> layers.

## Evidence Cards for an outbound-connection question

### Windows

- **Collector:** Sysmon EID 3 can retain source/destination address, port, protocol, and Process
  GUID for process-initiated TCP/UDP connections; [Microsoft documents it as disabled by
  default](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events).
  WFP Event 5156 is a different source: it records a connection WFP permitted and includes the
  application, direction, addresses, ports, protocol, and filter/layer identifiers.
- **Gate:** Record the Sysmon configuration or the specific WFP audit policy. Do not substitute
  one source's semantics for the other's.
- **Supported claim:** A selected process initiated a recorded connection, or WFP permitted the
  recorded connection.
- **Blind edge:** Content, a completed application transaction, and the process's reason for
  connecting still need separate corroboration.

### Linux

- **Collector:** Name the actual source: a scoped Linux Audit `connect` rule, or a particular
  eBPF/EDR sensor and its stated hook. [`connect(2)`](https://man7.org/linux/man-pages/man2/connect.2.html)
  is the native request boundary; its return state matters.
- **Gate:** Record the kernel, collector version, workload/container namespace, rule or sensor
  scope, retained fields, and health/loss state. An observation outside the workload's namespace
  is not an equivalent host-wide claim.
- **Supported claim:** The configured source recorded its connection request or result at that
  specific boundary.
- **Blind edge:** A syscall attempt does not explain what application code caused it, and a
  nonblocking request may need another observation to establish completion.

### macOS

- **Collector:** A [Network Extension filter data provider](https://developer.apple.com/documentation/networkextension/nefilterdataprovider)
  receives flows for connections opened by applications. Its
  [`NEFilterFlow`](https://developer.apple.com/documentation/networkextension/nefilterflow)
  contract includes source-app and source-process identity fields where available.
- **Gate:** Record the deployed provider, macOS version, authorization/approval state, subscribed
  capabilities, and retained flow fields. This is a distinct collection layer from Endpoint
  Security.
- **Supported claim:** The configured provider saw its documented flow and source identity.
- **Blind edge:** [Endpoint Security's `UIPC_CONNECT`](https://developer.apple.com/documentation/endpointsecurity/es_event_type_auth_uipc_connect)
  covers UNIX-domain sockets only. Without a suitable Network Extension or EDR surface, the
  general TCP/UDP connection question can remain `Telemetry blind`.

## Listener is not outbound traffic in reverse

An outbound `connect` detector cannot stand in for server exposure. On Linux, a process can
create a socket, bind a local address, then listen; on Windows and macOS, the corresponding
service/application and network-policy context matter as much as a later inbound connection.
For a listener investigation, correlate the process or service role, local address/port, policy
decision, and any later accepted/inbound flow. Do not label every listener as a backdoor simply
because it is network-facing.

## Authorized-lab validation checklist

- **State the question:** outbound connection, listener exposure, local IPC, DNS, protocol, or
  content. Do not use one event type as a proxy for all six.
- **Record the contract:** OS build, workload role, collector/provider and version, enabled
  configuration, scope, retained fields, and health/loss state.
- **Bounded action pass:** In an authorized lab, generate a benign, known connection or listener
  and confirm only the documented action and fields at the selected boundary.
- **Corroboration pass:** If claiming completion, protocol, or relationship to execution, collect
  a separate documented observation that supports that later fact.
- **Fail / Telemetry blind:** If the needed provider, policy, namespace scope, field, or health
  guarantee is absent, stop at the narrower supported claim and record the gap.
- **Do not retain:** raw packet captures, credentials, secrets, executable payloads, or live
  infrastructure configuration.

## Next use

Use this foundation with the [translation contract](00-translation-contract.md) when carrying a
network detection from Windows to Linux or macOS, or in the reverse direction. Use the
[telemetry cheat-sheet](../appendix/telemetry-cheatsheet.md) to choose a deployment tier, then
open a [threat walkthrough](../threats/00-overview.md) to decide why the connection matters in
context.
