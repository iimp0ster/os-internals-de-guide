#!/usr/bin/env bash
# macOS ESF capture (EDR tier) for the Execution / Persistence / Privilege-Escalation chapters.
# Requires macOS 13 Ventura or later (eslogger is built in) and runs under sudo.
# eslogger emits one JSON object per line (JSONL) to stdout.
#
# Apply:    sudo bash labs/macos/eslogger-cmds.sh <block>   (or copy a block's command)
# Inspect:  sudo eslogger <event> | head -1 | python3 -m json.tool
# List:     eslogger --list-events        ## the authoritative event-name set on THIS host
#
# captures/ is git-ignored — raw dumps stay out of the repo (see methodology.md).
set -euo pipefail
mkdir -p labs/captures

## ─── READ THIS FIRST — macOS capture is HARD-BLOCKED, and event names are not assumable ──
## • HARD PREREQUISITE (methodology): every macOS §6 rule is CAPTURE PENDING and stays that way
##   until this runs on ENTITLED APPLE HARDWARE. eslogger ships in macOS 13+ but the Endpoint
##   Security client it drives needs the host to permit ESF (a real Mac; SIP/TCC posture matters).
##   No CI, no VM-without-passthrough, no Linux/Windows substitute. These subscriptions are
##   AUTHORED-BUT-UNRUN: every §6 macOS cell in EMULATION-PLAN.md is ready=false / apple-hw-esf
##   precisely because this sensor cannot fire yet. Treat the blocks below as the capture spec
##   to execute the day Apple hardware exists — not as validated output.
## • DO NOT ASSUME EVENT NAMES. eslogger accepts the es_event_type_t short names (lowercased,
##   NOTIFY_ stripped: `exec`, `create`, `mmap`, …). ESF does NOT expose a generic "content write"
##   event the way auditd's -p w or Sysmon 11 might suggest. A file's CONTENTS changing is observed
##   as `close` (the modified-flag on NOTIFY_CLOSE), `create`, or `rename` — NOT a "write" event in
##   the sense of every byte. `write` exists as an event type but is high-volume (notify-only — like
##   every name here, since eslogger by design subscribes ONLY NOTIFY events, never auth) and fires
##   per-write-buffer, not per-logical-modification, so it is NOT what most file-modify rules should
##   anchor on. CONFIRM the exact set on hardware with
##   `eslogger --list-events` BEFORE trusting any name below. Every name this script could not
##   confirm against Apple's EndpointSecurity docs at authoring time is tagged 'unverified:' and
##   listed under "EMPIRICAL CHECKS" at the bottom.
## • VERSION FLOORS ARE GATES. Several events post-date macOS 13: BTM (login/launch item) events
##   need macOS 13+; TCC_MODIFY is 15.4+; the AUTHORIZATION petition/judgement and SUDO/SU events
##   are 14+. Subscribing to an event the running OS predates makes eslogger error out — so each
##   block names its floor and the §6 rule + named threat it feeds. Floors marked 'unverified:'
##   are the guide's own chapter claims, not re-confirmed against Apple release notes here.
## • eslogger streams until killed (Ctrl-C). One process per event-set; `tee` keeps a JSONL copy.
##   For a benign-baseline run (methodology: rule must NOT fire on baseline) capture the same
##   event-set on an untouched host and diff.

# ════════════════════════════════════════════════════════════════════════════════
#  EXECUTION (Part I)
# ════════════════════════════════════════════════════════════════════════════════

# --- exec + fork (process creation) ---------------------------------------------
# Each exec event carries full argv AND the signing identity (team ID, signing ID,
# cdhash, is_platform_binary) — context Windows surfaces only via separate lookups.
# The exec envp also carries DYLD_* (DYLD_INSERT_LIBRARIES) — the ATTEMPT anchor for
# the loader-hijack rule below; pair with `mmap` to prove the dylib actually LANDED.
# Floor: macOS 13+ (exec/fork are foundational ESF events).
# Feeds: 01-script-exec §6 'macOS — osascript inline script' (AMOS/osascript) ·
#        02-native-exec-loader §6 'macOS DYLD_INSERT_LIBRARIES Injection' envp branch (AMOS) ·
#        01-elevation §6 NOTIFY_EXEC branch (AEWP security_authtrampoline) ·
#        03-tcc-helpers §6 pre-15.4 fake-consent branch (osascript dialog, AMOS/Banshee).
sudo eslogger exec fork | tee labs/captures/macos-exec.jsonl

# --- mmap (+x library / anonymous-exec LANDING) ---------------------------------
# NOTIFY_MMAP reports a mapping with its protection + path. Two distinct §6 uses:
#   (1) loader hijack — a +x dylib mapped from a writable/non-system path PROVES the
#       DYLD_INSERT_LIBRARIES / weak-@rpath dylib actually loaded (envp shows only the
#       attempt; mmap is present on the entitled/unsigned target, ABSENT when Library
#       Validation blocks it). This is the "landing" half the plan pairs with the envp anchor.
#   (2) in-memory exec — an executable mapping NOT backed by a file in a NON-JIT process
#       is the macOS analog of the memfd/anon-exec cut. JIT runtimes legitimately map +x
#       anon memory, so a JIT baseline is mandatory to separate signal from noise.
# Floor: macOS 13+ (NOTIFY_MMAP). unverified: exact +x/anon discrimination is done in
#        post-processing on the event fields, not by eslogger filtering.
# Feeds: 02-native-exec-loader §6 'macOS DYLD_INSERT_LIBRARIES' landing + T1574.004 complement
#        (AMOS dylib injection; Wardle-style weak/@rpath hijack) ·
#        03-in-memory-exec §6 'macOS — executable anonymous memory in a non-JIT process'.
sudo eslogger exec fork mmap | tee labs/captures/macos-mmap-exec.jsonl

# ════════════════════════════════════════════════════════════════════════════════
#  PERSISTENCE (Part II)
# ════════════════════════════════════════════════════════════════════════════════

# --- create (plist / helper / login-item file landing) --------------------------
# NOTIFY_CREATE is the primary file-landing anchor for the persistence "config write"
# cut on macOS. The config FILE coming into existence is the invariant — the manager
# invocation (launchctl) is secondary. Filter destinations in post-processing:
#   ~/Library/LaunchAgents, /Library/LaunchAgents, /Library/LaunchDaemons       (service/daemon)
#   /Library/PrivilegedHelperTools  + /Library/LaunchDaemons                    (privileged helper)
# NOTE: NOTIFY_CREATE fires on a NEW file. An APPEND to an existing file (shell rc) does
#       NOT create — see the file-modify block below; do not anchor rc-append rules on create.
# Floor: macOS 13+ (NOTIFY_CREATE).
# Feeds: 01-service-daemon §6 'macOS LaunchAgent/Daemon Plist Created' (AMOS LaunchAgent) ·
#        02-scheduled §6 'macOS Scheduled LaunchAgent/Daemon Plist Created' (Silver Sparrow) ·
#        03-tcc-helpers §6 helper rule '/Library/PrivilegedHelperTools' (Pearcleaner LPE) ·
#        03-login-shell-hooks §6 Login-Item arm (file-landing half).
sudo eslogger exec fork create | tee labs/captures/macos-create.jsonl

# --- file modification of rc / auth.db / TCC.db (close-modified + rename) --------
# THE TRAP: there is no clean "file content written" ESF event. A modify is observed as
# NOTIFY_CLOSE with the `modified` flag set (the close that flushes the write), or as
# NOTIFY_RENAME (atomic write = write-temp-then-rename). NOTIFY_CREATE misses the common
# case because these targets ALREADY EXIST (rc files, the dbs) and the attack APPENDS /
# rewrites in place. Anchor rc-append + db-poison rules on close(modified)/rename, then
# filter TargetFilename in post-processing:
#   ~/.zshrc ~/.zprofile ~/.bash_profile ~/.bashrc        (shell rc append — Green Lambert zsh)
#   /var/db/auth.db, /Library/Security/SecurityAgentPlugins/  (auth mechanism wire — SecurityAgent plugin)
#   ~/Library/Application Support/com.apple.TCC/TCC.db     (TCC.db poison — powerdir; sqlite3/$HOME
#                                                            write BYPASSES tccd → emits this, NOT tcc_modify)
# unverified: that `close` is the correct/most-reliable modify event for ALL three targets
#   (sqlite WAL/journal may surface as create/rename of -wal/-journal siblings instead, and an
#   editor may rename-over). Confirm on hardware which event fires per target; rename is included
#   so atomic-write paths are not missed.
# Floor: macOS 13+ (NOTIFY_CLOSE / NOTIFY_RENAME).
# Feeds: 03-login-shell-hooks §6 'macOS Shell RC Modified' (Green Lambert zsh rc) ·
#        02-polkit-authz §6 file_event auth.db/SecurityAgentPlugins branch (SecurityAgent plugin) ·
#        03-tcc-helpers §6 NOTIFY_WRITE complement (powerdir TCC.db poison).
sudo eslogger close rename create | tee labs/captures/macos-filemod.jsonl

# --- btm_launch_item_add (Login / Launch item registration) ----------------------
# NOTIFY_BTM_LAUNCH_ITEM_ADD is the HIGH-FIDELITY persistence signal: macOS's Background
# Task Management records the registration of a launch agent/daemon OR a Login Item with
# the responsible/instigator process — semantic registration, not just a file landing, so
# it survives plist writes that NOTIFY_CREATE might miss (and names who did it).
# Floor: macOS 13.0+ (BTM introduced with Ventura) — corroborated: Apple Dev Forums 720468 +
#        Cybereason eslogger blog shows a live `sudo eslogger ... btm_launch_item_add`. unverified:
#        that this short name is exposed on YOUR build — confirm via --list-events; BTM telemetry
#        availability has shifted across point releases.
# Feeds: 03-login-shell-hooks §6 Login-Item arm (Adload Login Item) ·
#        01-service-daemon / 02-scheduled §6 BTM complement note (LaunchAgent registration).
sudo eslogger btm_launch_item_add | tee labs/captures/macos-btm.jsonl

# ════════════════════════════════════════════════════════════════════════════════
#  PRIVILEGE ESCALATION (Part III)
# ════════════════════════════════════════════════════════════════════════════════

# --- setuid (euid→0 consent elevation) ------------------------------------------
# NOTIFY_SETUID is the KERNEL-MANDATORY transition signal: it fires on euid→0 regardless
# of broker, so it catches the AEWP path (security_authtrampoline validates the prompt,
# then the child runs as root) where the userspace NOTIFY_SUDO/SU would be evaded by an
# attacker's own sudo. Pair with the `exec` block above (NOTIFY_EXEC of
# security_authtrampoline) to bind the transition to its broker.
# Floor: macOS 12.0+ (NOTIFY_SETUID) — corroborated: Apple developer docs
#        es_event_type_notify_setuid (matches chapter 01-elevation §6). unverified: whether setuid
#        and seteuid are DISTINCT subscribable event types — host-empirical; confirm via --list-events
#        (NOTIFY_SETUID is the authoritative euid→0 anchor regardless of the answer).
# Feeds: 01-elevation §6 'macOS Elevated Execution with Prompt (AEWP)' NOTIFY_SETUID anchor
#        (AMOS / Atomic Stealer / Banshee consent elevation, T1548.004).
sudo eslogger setuid exec | tee labs/captures/macos-setuid.jsonl

# --- tcc_modify (TCC consent record via tccd) -----------------------------------
# NOTIFY_TCC_MODIFY fires when tccd records a grant/revoke — the PRIMARY branch of the TCC
# rule (a consent record written through the sanctioned path). It does NOT fire on access,
# nor for already-entitled binaries (XCSSET-style inheritance is invisible here), nor when a
# planted/poisoned TCC.db is read directly (that bypasses tccd → see the file-modify block).
# Floor: macOS 15.4+ ONLY (NOTIFY_TCC_MODIFY) — corroborated: objective-see.org blog_0x7F "Apple
#        finally adds TCC events" (matches chapter 03-tcc-helpers §6). A hard gate: on <15.4 this
#        subscription will FAIL and the rule has NO SIEM fallback — so still gate on sw_vers ≥ 15.4
#        on the running host before subscribing.
# Feeds: 03-tcc-helpers §6 PRIMARY branch EventType 'tcc_modify' (powerdir consent record).
sudo eslogger tcc_modify | tee labs/captures/macos-tcc.jsonl

# --- authorization petition / judgement (AuthZ decision tier) -------------------
# Decision-tier complement for the policy-broker chapter: the petition (id 129) and judgement
# (id 130, results[] {right, rule_class, granted}) expose the SecurityAgent/authd decision an
# AuthorizationCopyRights call drives — the act, not just the plugin file landing.
# Floor: unverified: macOS 14+ (NOTIFY_AUTHORIZATION_PETITION / _JUDGEMENT) per 02-polkit-authz §6.
#        unverified: the exact eslogger short names — likely `authorization_petition` /
#        `authorization_judgement` — confirm via --list-events; ESF-pipeline only, no SIEM fallback.
# Feeds: 02-polkit-authz §6 JUDGEMENT complement (SecurityAgent-plugin auth-chain wire).
sudo eslogger authorization_petition authorization_judgement \
  | tee labs/captures/macos-authz.jsonl

# --- xpc_connect (privileged-helper IPC — connection only) ----------------------
# NOTIFY_XPC_CONNECT is captured as a documented BLIND SPOT, not a detection anchor: it reports
# the CONNECTION to a root helper, never the message selector/arguments (the actual privileged
# act is off-telemetry). Stream it only to evidence the gap and to correlate connect→root work.
# Floor: unverified: macOS 14+ (NOTIFY_XPC_CONNECT) — confirm name + floor via --list-events.
# Feeds: 03-tcc-helpers §6 'NO rule can express the XPC abuse' gap note (Pearcleaner/Plugin Alliance LPE).
sudo eslogger xpc_connect | tee labs/captures/macos-xpc.jsonl

# ════════════════════════════════════════════════════════════════════════════════
#  EMPIRICAL CHECKS — run FIRST on the entitled Mac, before trusting any block above
# ════════════════════════════════════════════════════════════════════════════════
# These resolve every 'unverified:' tag. Until they pass on hardware, the macOS §6 rules
# stay CAPTURE PENDING (methodology hard prerequisite).
#
#   1. Authoritative event-name set for THIS build:
#        eslogger --list-events
#      Confirm the exact short names this script uses are present:
#        exec fork create close rename mmap setuid tcc_modify xpc_connect
#        btm_launch_item_add authorization_petition authorization_judgement
#      (write exists but is notify-only + high-volume/per-buffer — do NOT swap it in for file-modify.)
#   2. File-modify ground truth — which event actually fires per target? Touch each in a lab:
#        echo '# test' >> ~/.zshrc                         ## expect close(modified) and/or rename
#        sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'pragma user_version;'  ## WAL?
#      Capture `close rename create` and inspect which event names the path. Re-anchor rc/db rules
#      on whatever actually fires (close-modified vs rename vs a -wal/-journal sibling create).
#   3. Version floors — confirm against the running build (sw_vers) before subscribing.
#      Three floors are corroborated against a primary/independent source (cite, don't re-derive):
#        tcc_modify          → 15.4+   corroborated: objective-see.org blog_0x7F "Apple finally adds
#                                      TCC events" (else subscription errors; rule has no fallback)
#        btm_launch_item_add → 13.0+   corroborated: Apple Dev Forums thread 720468 + Cybereason
#                                      eslogger blog (live `sudo eslogger ... btm_launch_item_add`)
#        setuid              → 12.0+   corroborated: Apple developer docs es_event_type_notify_setuid
#      One floor remains UNCONFIRMED — it is the guide's own chapter claim, not pinned to an Apple
#      availability annotation (Apple doc JSON strips introducedAt), so resolve it ON HARDWARE here:
#        authorization_petition / authorization_judgement / xpc_connect → claimed 14+; subscribe-and-
#                                      check on the running build (sw_vers) — keep 'unverified:' until then.
#   4. mmap discrimination — verify the event carries enough (prot bits, path, file-backed flag)
#      to separate a +x dylib map from benign maps and a JIT +x anon map from an injection.
#
# --- Helpers (run individually) -------------------------------------------------
# Pretty-print the first event of a type to inspect the schema:
#   sudo eslogger create | head -1 | python3 -m json.tool
#
# Unified log (SECONDARY — no reliable per-syscall event; use for auth/context only):
#   log stream --style ndjson --predicate 'process == "tccd"'
#   log show --last 1h --predicate 'eventMessage CONTAINS "osascript"' --style ndjson
