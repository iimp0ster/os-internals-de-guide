# Filesystem & staging

Staging is an evidence question before it is a path question. A location can focus an
investigation, but it does not say who wrote the object, why it was written, whether it is
trusted, or whether anything later executed it. **A file write is not execution.**

## Five boundary comparison

| Boundary / question | Windows | Linux | macOS |
|---|---|---|---|
| User-writable | A user profile or shared application-data location can be a pivot; confirm the local ACL and writer. Sysmon File Create is available only when [installed and filtered](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon). | `$HOME` or a role-specific application directory may be meaningful, but inspect the account, namespace, image, and local permissions. A Linux Audit rule must be scoped to the relevant object and [audit configuration](https://man7.org/linux/man-pages/man8/auditctl.8.html). | A user-owned `~/Library` location can be a pivot; inspect its owning user and application role. Where available/configured, an [Endpoint Security client](https://developer.apple.com/documentation/endpointsecurity/es_new_client%28_%3A_%3A%29) can subscribe to the relevant file event; [Gatekeeper](https://support.apple.com/en-ca/guide/security/sec5599b66df/web) is a separate provenance/control question. |
| Temporary / runtime | A per-user or service temporary area needs parent-process and service-context review, not a path-only verdict. | `/tmp`, `/var/tmp`, runtime directories, and `/dev/shm` have different mount, image, and `noexec` conditions; service, cloud, container, developer, and workload roles determine which is relevant. Linux Audit scope depends on the configured rule, ABI, directory, and mount. | A temporary or per-user runtime location is a change-discovery pivot. FSEvents can indicate hierarchy changes but is not writer attribution and can expose [dropped-event flags](https://developer.apple.com/documentation/coreservices/file_system_events/1455361-fseventstreameventflags). |
| System-wide application | Machine-wide application data or a vendor directory requires local ACL, installer, signer, and service-owner context. [Sysmon Event 11](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) records a configured file create/overwrite, not later use. | System-wide application content may belong to a package, service, or workload. Treat package ownership and container/bind-mount context as local inspection questions rather than a desktop analogue. | An application bundle or shared support location requires bundle ownership, signing, and policy context; [Gatekeeper](https://support.apple.com/en-ca/guide/security/sec5599b66df/web) provenance applies only where its documented control conditions apply. |
| Service / application bundle | A service working directory or application-owned data area needs the service identity and parent/service chain. | A systemd-managed service, container image, cloud workload, CI runner, or developer tool can own the relevant boundary; inspect the unit, namespace, bind mount, and runtime identity. [Red Hat's audit guidance](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening) illustrates that records and fields depend on configured audit scope. | An `.app` bundle or application-support tree needs the bundle identity, code-signing/provenance context, and later process evidence; do not infer a bundle launch from a file action. |
| Removable / network-backed | A removable volume or network share needs share/drive provenance, writer identity, and session context. | A removable device, NFS/SMB mount, or container bind mount is role- and mount-specific; determine mount options, owning workload, and whether the collector covers that mount. [Audit rules document mount-point behavior](https://man7.org/linux/man-pages/man7/audit.rules.7.html). | A removable or network-backed volume is a local policy and provenance question. Use an [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) file-operation observation only where deployed/subscribed; [FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events/1455361-fseventstreameventflags) remains a hierarchy-change layer rather than a process-attributed equivalent. |

> **Analogue verdict.** For a configured created/overwritten-file action, [Sysmon File Create](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) is often the **closest analogue** Windows evidence anchor. [Linux Audit/auditd](https://man7.org/linux/man-pages/man8/auditctl.8.html), or a separately named sensor, is a **partial analogue** whose support depends on the local role and rule, syscall, directory, mount, and ABI scope—not an equivalent evidence contract. On macOS, **no direct equivalent** can be the correct conclusion at the deployed collection layer; process attribution is `Telemetry blind` when the applicable [Endpoint Security event subscription](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) or [client](https://developer.apple.com/documentation/endpointsecurity/es_new_client%28_%3A_%3A%29) is not deployed or subscribed. [FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events/1455361-fseventstreameventflags) remains hierarchy-change evidence rather than process attribution. None of these collectors or event surfaces are parity claims.

These examples are deliberately curated. For dense path, ACL, attribution, and field lookup,
use the [staging appendix](../appendix/staging-and-abused-paths.md); re-check local build,
image, distribution, mount, policy, role, and collector availability before treating an example
as a baseline.

```admonish warning title="A path is a pivot, not proof"
A path match alone establishes neither maliciousness nor execution. A configured collector can
support a bounded filesystem action; the next conclusion requires the surrounding identity,
object, control, and later-event context.
```

## Evidence Cards for a user-writable staging question

### Windows

1. **Collector** — Configured Sysmon File Create (Event 11), with File Create Stream Hash
   (Event 15) only where that separate event is retained. Microsoft documents the event
   definitions in its [Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events).
2. **Control / gate** — Sysmon must be installed and filtering must retain the relevant event;
   inspect the local ACL, writer identity, parent process, and any available named-stream
   provenance.
3. **What it proves** — The collector recorded its documented create/overwrite or named-stream
   action for the retained object.
4. **Blind edge** — It does not establish malicious intent, that the writer obtained the object
   from a specific source, or that a process later executed it.

### Linux

1. **Collector** — Linux Audit/auditd with a rule deliberately scoped to the local syscall,
   directory, mount, and ABI; a separate eBPF/EDR surface must be named independently.
2. **Control / gate** — `auditd` must be running and the rule must cover the relevant scope.
   The [auditctl manual](https://man7.org/linux/man-pages/man8/auditctl.8.html) documents rule
   and mount behavior; do not assume a directory watch is universal visibility.
3. **What it proves** — The retained audit records support the action and fields actually
   emitted by that configured rule, such as a `PATH`, identity, or syscall record.
4. **Blind edge** — A record does not turn a Linux service, cloud, container, developer, or
   workload boundary into a workstation analogue; it also does not prove execution or intent.

### macOS

1. **Collector** — Where available/configured, an Endpoint Security client subscribed to the
   relevant create, write, rename, or exec notification; Apple documents distinct event types in
   its [Endpoint Security event reference](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t).
2. **Control / gate** — The deployed client needs the applicable Endpoint Security entitlement,
   approval, subscriptions, and supported OS/SDK contract; consult Apple's
   [client-creation documentation](https://developer.apple.com/documentation/endpointsecurity/es_new_client%28_%3A_%3A%29)
   for the collection gate.
3. **What it proves** — The subscribed Endpoint Security notification supports its documented
   file operation or execution observation; Gatekeeper supplies separate provenance/control
   context where applicable.
4. **Blind edge** — FSEvents does not establish the creating process, and an unavailable or
   unsubscribed Endpoint Security event is `Telemetry blind`, not proof that the action did not
   happen.

The card order is intentional: **Collector**, **Control / gate**, **What it proves**, then
**Blind edge**. These cards are not collector parity claims.

## Capture staging context before interpreting a path

For every candidate object, record:

- **Actor / writer** identity and the account, service, workload, or user session it represents.
- **Parent / service** or other initiating context, including the parent process where the
  collector supplies it.
- **Object** and a stable identifier where available, plus the target path before and after a
  rename.
- **Operation** (`create`, `write`, `rename`, or a later execution observation) and its
  **Result** / return status where supplied.
- **Ownership / permissions** and the relevant mount, container, service, network-share, or
  application-bundle boundary.
- **Trust / provenance**, such as installer/package context, available signer information, or
  applicable native provenance control.
- **Relation to later execution** or recurrence: identify it as missing until separate evidence
  establishes it.

Sysmon may provide the fields its selected events retain; Linux Audit fields depend on the
configured rule and audit record; Endpoint Security fields depend on the subscribed event and
deployed client. Enrichment is therefore a requirement to state, not an assumption to hide.

## Evidence ladder: create is not a causal chain

| State | Bounded claim | Collector / control and gate | Still missing |
|---|---|---|---|
| **create** | A configured collector recorded its defined create or overwrite action. | [Sysmon Event 11](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events) when installed/filtered; Linux Audit only when a running, [scoped rule](https://man7.org/linux/man-pages/man8/auditctl.8.html) captured it; [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) where deployed/subscribed. | Intent, full writer provenance, and any later data modification or execution. |
| **write** | A configured collector recorded a data-write action where that surface exposes it. | Linux collection depends on the [selected rule/sensor](https://man7.org/linux/man-pages/man8/auditctl.8.html); [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) has separate write semantics where available/configured; [FSEvents](https://developer.apple.com/documentation/coreservices/file_system_events/1455361-fseventstreameventflags) change discovery is not process attribution. | Whether the write completed as intended, which bytes matter, and whether the object was later renamed or used. |
| **rename** | A configured collector recorded a name/path transition or a retained record that must be correlated with the object. | [Audit](https://man7.org/linux/man-pages/man7/audit.rules.7.html) and [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t) semantics depend on the selected event/rule; correlate pre/post paths and available identifiers. | That the renamed object is the same logical content, was executed, or was made persistent. |
| **execution** | A separate execution observation can support a later execution claim. | Route to [Execution graphs](../execution/00-intro.md) and [Native execution & the loader](../execution/02-native-exec-loader.md) for the owner-specific process/loader evidence. | Intent, impact, and any recurring trigger unless separately corroborated. |

Collectors can emit repeated writes, batch or buffer records, expose equal or coarse timestamps,
lose events, and report path reuse or rename separately. Displayed timestamp order alone does
not prove causal order. Correlate available process/identity, object or file identifiers,
operation result, and target path before/after rename for a bounded action observation. A causal
or ordered sequence additionally needs an explicit, collector-appropriate health measurement for
the test interval; without one, label ordering `Telemetry blind` while retaining any supported
single-action observation.

A recurring or autostart conclusion is also outside this page's ownership: route it to
[Persistence graphs](../persistence/00-intro.md). For additional paths, ACLs, attribution, and
field-level lookup after the evidence ladder, return to the
[staging appendix](../appendix/staging-and-abused-paths.md).

## Authorized-lab validation checklist

- **Scope:** Use an authorized isolated lab and a clearly benign synthetic text artifact only.
  Record the OS build and collector version/configuration state, not raw event output.
- **Bounded action:** Create, write, and rename that harmless text artifact within the selected
  local boundary. This validates collection only; it does not instruct execution of a staged
  artifact.
- **Expected event shape:** The configured collector should report the documented bounded action
  and the fields it supplies for identity/parent, action, target object/path, result, time,
  available object identifier, and policy/entitlement/mount context. Document any emitted
  dropped/lost-event state separately; its absence is not proof of a loss-free interval.
- **Inspect:** Confirm the action semantics and required fields, then check that the object and
  process/identity correlation is sufficient for the narrow claim. For an ordering claim, also
  record a collector-appropriate interval health measurement: for example, Linux Audit's
  documented lost counter before and after the action, or documented FSEvents drop/rescan state
  where that state is available.
- **Bounded action pass:** The configured collector produces the documented action with required
  fields. This supports that action observation only.
- **Sequence pass:** Assert causal or ordered sequence only when the interval health measurement
  establishes the required no-loss condition. If the collector has no health signal that can
  establish it, record ordering as `Telemetry blind` while retaining a supported bounded action.
- **Fail / Telemetry blind:** Treat missing events, missing required fields, absent
  configuration, unmet entitlement/policy, or a health measurement indicating loss as a failed
  collection contract for the affected claim.
- **Do not retain:** raw logs, credentials, secrets, executable payloads, capture content, or
  live infrastructure configuration.
