# Stage 1 Firefox input candidates and fresh profile seeds

Status: two final-source instrumented launches pass the unchanged local-page
functional endpoint, with identical initial private profile seeds. This is a
pathname/mapping audit. It does not qualify cold-cache Firefox, complete input
closure, namespace-aware file identities, wrapper overhead or acceleration.

## Separate audit and reset primitive

`bench/browser_inputs.py` wraps the existing [Firefox endpoint](browser-endpoint.md)
with a private launcher. The browser still uses its normal sandbox settings and
the same local HTML/SVG marker. A fresh HOME/profile/config/data/cache is created
for each launch. Before executing the browser, the launcher checks exactly six
seed nodes: HOME, four directories and `profile/user.js`. Relative node names,
mode, UID/GID, file size/content and the exact allowed preferences must match
across both seeds. Extra generated state, symlinks, altered preferences and
oversized seed nodes cause refusal. Old output directories are not reused.

This proves identical generated logical starting seeds, not complete browser
state reproducibility. Inodes, timestamps, random state, runtime services,
system file caches and later generated profile contents differ or remain
uncontrolled. Cleanup is not a normal browser quit or profile-durability test.

The unchanged endpoint sees the strace supervisor in place of its direct
launcher process. The audit additionally identifies the actual Firefox main
executable as a direct child in the owned transient cgroup and verifies its
effective/permitted/ambient capabilities are zero. At readiness, it inventories
executable and mapped path strings from owned group members. No process snapshot
was unreadable in the final run. Group cleanup still runs if optional audit
capture fails; capture failures are retained and prevent audit acceptance.

strace 7.2 follows forks/threads and records pathname syscalls and mmap, with
decoded descriptor paths. Read/write payload syscalls are not traced. The
[strace manual](https://github.com/strace/strace/blob/master/doc/strace.1.in)
documents fork following and `PTRACE_O_EXITKILL`; the latter prevents remaining
tracees from surviving their tracer. SIGTERM cleanup plus that option can kill
tracees, so this audit does not make a graceful-exit claim. Tracing changes
execution and timings; instrumented endpoint times are not speed evidence.

## Final observed set

| Item | Final-source result |
| --- | ---: |
| Functional endpoint launches | 2 passing |
| Identical initial seed nodes per launch | 6 |
| Trace files | 709 |
| Aggregate trace bytes | 5,237,189 |
| Observed pathname candidates | 1,099 |
| Unique host-resolvable regular `/usr` candidates | 395 |
| Their logical bytes | 730,717,601 |
| Unique host-resolvable regular `/etc` candidates | 14 |
| Their logical bytes | 198,561 |
| Escaped/deleted annotations rejected by the parser | 0 |

These are candidates. Successful decoded descriptor annotations, exec paths and
live mapping strings supplement one another, but a pathname by itself does not
prove which inode a process in another mount namespace accessed. Hashes in the
private manifest describe the host-resolved candidate at audit time. They do
not establish equivalence with every sandbox view or a complete byte-access
trace. No nested path prefix is stripped and assumed to identify a host file.

The 83 candidates outside the usual approved roots comprise 61 nested sandbox
setup paths, 13 font-cache paths, eight memory-backed paths and the host root
directory. Sandbox setup exposes temporary old-root/new-root names. Private
review classifies them but does not canonicalize their identities. Directories,
failed-path decisions, runtime/kernel state, IPC and services outside the owned
cgroup remain part of the unresolved closure.

This changes the next fixture design in two ways: namespace-aware identities
must be qualified before accepting aliases, and the 730,717,601-byte `/usr`
candidate set already exceeds the earlier 512 MiB native-fixture bound. A 1 GiB
per-corpus bound is proposed for a separate private Firefox fixture, with the
existing 72 GiB native-construction free-space floor. It has **not** been applied
or used to build a copied browser corpus. That proposal does not expand the
production pass/day maintenance quota. It must account for retained attempts,
metadata and write/space costs before construction.

## Isolation, bounds and retained failures

Both launches use only loopback IP networking, with no default route. Existing
desktop Unix IPC remains accessible; this is not a whole-host network air gap.
The owned transient unit has a 3 GiB memory limit, no swap allowance, 512-task
limit and 180-second lifetime. The audit requests no CPU quota. The actual main
process stays in that group, and cleanup reports no remaining owned browser
processes or escalation by the cleanup routine. `PTRACE_O_EXITKILL` still applies.

The audit checks at most 1,024 trace files and 64 MiB aggregate traces while
polling local HTTP requests and again after cleanup. This is a sampled stop
condition, not a filesystem quota; transient overshoot is possible. Candidate
paths are capped at 8,192; unique regular host-candidate hashing is capped at
1 GiB, with 256 MiB per supported file and a 64 GiB free-space floor.

The first attempt applied a 16 MiB per-file limit to the entire application.
That also constrained Wayland shared-memory files, producing a file-too-large
failure and browser crash. An audit-capture exception obscured the original
endpoint exception; the browser log preserves the failure. This attempt remains
intact. The corrected second attempt passed; the final third attempt also
qualifies corrected error handling and records the identity/limit boundaries.
The application-wide file limit was removed, without changing browser sandbox
settings or global limits.

The Linux suite passes 148 tests. One initial syntax-cache write failed because
earlier root experiments had created non-writable bytecode cache files in the
staged source. Syntax verification then passed with a fresh user-owned Python
bytecode prefix; no source or production permissions were changed. All seven
installed hashes, original boot configuration, active power/timer, 5000 us
setting and quota history still verify. [Reviewed evidence](evidence/stage1-browser-inputs.json)
contains aggregate results, source hashes, retained attempt descriptions and
explicit incomplete qualifications. Raw paths/traces/profiles stay private.

## Reproduction and next work

Use the matching Linux desktop session and strace. Choose a new private output:

```sh
python3 bench/browser_inputs.py audit --output /absolute/owned-lab/new-firefox-audit
```

The endpoint and page sources remain unchanged. Next, qualify cross-namespace
file identity, selected native browser metadata and copied-file cache controls;
then measure wrapper cost before any policy comparison. Private package updates,
game/streaming fixtures and request-observer lifecycle/overhead/attribution also
remain required. Stage 1 and the complete ten-stage goal remain active.
