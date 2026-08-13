# Translation contract: the Foundation legend

> **Read this first.** This page is the legend and rubric for the Foundation layer. The pages
> that follow describe the building blocks of each operating system—filesystem, process/loader,
> network, and later foundations. Use this rubric to read their comparison tables without
> mistaking a familiar API, syscall, collector, or event name for an equivalent detection claim.

A shared threat objective does not create a shared operating-system story. Platform adoption,
endpoint role, protected assets, safeguards, and available visibility can all change the native
mechanism and the strongest defensible conclusion. This is a behavior-first comparison aid, not
a one-to-one API, syscall, collector, or event lookup.

## How to use this legend

For every Foundation page, read across the three OS columns in this order:

1. **Behavior:** What shared question is the page trying to answer?
2. **Native boundary:** What object, mechanism, or OS transition carries that behavior locally?
3. **Evidence contract:** Which collector/control can observe it, what must be configured, and
   what narrow fact does its event actually prove?

The result can be a closest analogue, a partial analogue, no direct equivalent, or a telemetry
blind spot. Those are conclusions—not gaps the reader needs to paper over.

## Start with the question, not the familiar event

| Lens / question | Windows | Linux | macOS |
|---|---|---|---|
| Shared objective | Did an actor place content where a user, application, or service could later use it? | Did an actor place content in the relevant host, service, container, developer, or workload context? | Did an actor place content where a user or application bundle could later use it? |
| Native object / mechanism | A file-system object and its access-control context; a later process start is a separate fact. | A VFS object in a filesystem, mount, or namespace; a later `exec` is a separate fact. | A file-system object; Gatekeeper provenance and a later Endpoint Security execution observation are separate facts. |
| Named collector or control | Configured [Sysmon File Create / File Create Stream Hash](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events). | [Linux Audit rules](https://man7.org/linux/man-pages/man7/audit.rules.7.html) scoped to the relevant syscall, directory, mount, and ABI, or a separately declared eBPF/EDR surface. | Where deployed and subscribed, [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security); [Gatekeeper](https://support.apple.com/en-ca/guide/security/sec5599b66df/web) is a provenance/control boundary, not a file-event collector. |
| Collection gate | Sysmon must be installed and its event filters must retain the relevant event. | `auditd` must be running and the rule must cover the local scope; a named eBPF/EDR surface has its own deployment gate. | Endpoint Security availability depends on the deployed client, approval, entitlement, subscribed event, and supported OS/SDK contract; do not substitute FSEvents for process-attributed proof. |
| Bounded proof / non-proof | A retained file event supports the documented file action, not intent, execution, or impact. | A retained audit record supports only the action and fields captured by that configured rule; it is not a universal file view. | An Endpoint Security notification, where available/configured, supports its documented operation; [FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events) is hierarchy-change discovery and can report dropped events. |
| Analogue verdict | Windows implementation for this example. | Usually a **partial analogue** until the local role, namespace, mount, and collector are known. | **Closest analogue**, **partial analogue**, or **no direct equivalent** can all be correct depending on the control and collector available. |

The columns describe distinct evidence contracts. A missing event can mean an unconfigured or
blind collector; it does not establish that the behavior was absent.

## Evidence Card

Review every source and proposed detection in this exact order:

1. **Collector** — Name the native surface actually supplying the observation. Sysmon,
   Linux Audit/auditd, a separately declared eBPF/EDR sensor, Endpoint Security, and FSEvents
   answer different questions.
2. **Control / gate** — Record installation, filtering, rule scope, collector state, local
   policy, entitlement/approval, platform support, and any relevant identity or mount boundary.
3. **What it proves** — State the narrow action or control decision that the retained fields
   support.
4. **Blind edge** — Name the next conclusion the observation cannot establish alone, such as
   provenance, intent, successful execution, persistence, impact, or a missed/lost event.

Use the guide's labels precisely: `source-backed` means a cited public source supports the
claim; `experimental` needs local testing; `unverified:` needs live confirmation; and
`Telemetry blind` means the available collector cannot establish the behavior. See
[Methodology](../methodology.md) for the shared vocabulary and validation standard.

## Apply the rubric to a known detection idea

1. **Shared objective:** What must happen independent of operating system?
2. **Starting-OS anchor:** On the OS you already know—Windows, Linux, or macOS—which local
   object/action and which collector or control supports the starting observation?
3. **Target-OS hypothesis:** On the OS you need to investigate, what native object, identity,
   provenance, or control boundary fits the actual endpoint, service, cloud, container,
   developer, or workload role? Which collector could observe it?
4. **Likely actor / role:** Which user, service, application, workload, or management plane
   would make the action meaningful?
5. **Control / gate:** What version, collector configuration, rule scope, policy, mount,
   entitlement, approval, or retention condition must hold?
6. **Supported claim:** What narrow fact does the evidence establish, and what does it not
   establish?
7. **Blind edge:** Is the gap an absent native mechanism, an unconfigured collector, or a
   collector that is genuinely blind to the needed fact?
8. **Next corroboration:** Which execution, persistence, identity, or environment evidence is
   still needed?
9. **Verdict:** Record **closest analogue**, **partial analogue**, or **no direct equivalent**.
    The last outcome is a complete, useful result—not a blank cell to fill.

Translate only into the OS or OSes in scope; completing all three columns is not a requirement.
For example, a Windows file-create idea may become a Linux audit-rule hypothesis scoped to a
specific service mount, while a Linux `execve` observation may become a Windows process-creation
or macOS Endpoint Security execution question. A macOS execution observation can likewise end
at a Windows process-creation record or a Linux success-side exec tracepoint. None is
automatically an equivalent evidence contract, and any target can legitimately end at
`Telemetry blind` until its collection gate changes.

## Continue into the Foundation building blocks

[Filesystem & staging](01-filesystem-and-staging.md) is the first application: it applies the
rubric to landing boundaries. Next, [Process & loader behavior](02-process-and-loader-behavior.md)
applies it to code start and image loading, and [Network & connection behavior](03-network-and-connection-behavior.md)
applies it to flows, connection requests, and listeners. In each case, the useful conclusion
comes from the native boundary, collector, gate, and corroboration—not the familiar event name.
