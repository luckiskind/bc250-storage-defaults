# Stage 1: independent wake-function witness

The separate diagnostic passes **8 native controls** and all **322 Linux
tests**. Four positive cases perform **256 cold 4 KiB accesses** across plain/
encoded files and buffered reads/mappings. Each of the 256 observed blocked
segments has actual request/vector proof, an independently observed successful
`try_to_wake_up` call and a task-state observation in its waking trace.

**No early-wake overlap occurred.** Every observed waking task-state sample
had `on_cpu == 0`. This qualifies the ordinary witness path and its controls;
it does not qualify native early overlap or establish its frequency in normal
applications. The sample was not extended or repeated to seek a particular
order. Total observer cost and whole-application critical paths remain open.
No new accelerator gain or default promotion is claimed.

## Independent evidence and limits

Three additional programs observe actual wake-function entry/return and the
kernel's waking trace, giving 31 owned probes and 14 temporary context maps.
They join the exact selected task/active sleep slot and current queued-folio
callback. Entry and return retain a private anonymous attempt identity; a
successful return is mandatory for the corresponding waking record.

The waking witness records target `on_cpu` and `on_rq` fields between entry
and snapshot-completion clocks. These are **separate reads**, not a joint
atomic snapshot. The actual deployed BTF function signature and state-field
types are checked before compilation. No task is dereferenced after the wake
function returns; only the retained pointer value is compared.

To qualify an early overlap, the existing causal reader must first classify
the early order. The separate wake-function evidence must then show a target
`on_cpu == 1` observation whose completion clock precedes switch-out. An
on-CPU observation only at wake-function entry is insufficient, as is a
waking snapshot that completes after switch-out. Missing, failed, ambiguous
or reused evidence fails the witness screen. The classifier still reports
early-handoff storage-blocked duration as unknown.

The existing [handoff source/reader](handoff-wait.md), earlier [compact
reader](compact-wait.md) and [failed cost experiment](compact-wait-cost.md)
remain unchanged. Checked loader generation adds the three programs and
witness configuration/counters. The old request/vector and scheduler proof
are preserved. This extra diagnostic is opt-in and supplies no transferable
cost qualification for the smaller observer.

## Fixed native experiment

The four positive cases and four negatives are frozen before collection.
Each positive worker performs 64 operations on a new private 8 MiB file,
at offsets `((pass * 37) % 2048) * 4096`. Plain and encoded files contain
identical bytes, have no shared extents and have verified encoding.

Every operation evicts only its private file's data and checks zero residency
before reading/mapping. A separately computed rolling content hash verifies
all 256 KiB delivered by each worker. The worker retains the actual inherited
file description and its process/affinity through observer detach. These
controls do not establish cold filesystem metadata or SSD-internal caches.

The negatives verify same-inode/different-open rejection, explicit witness
omission, a four-record cap and forced observer exit. Omitting the witness
keeps the original read valid but fails witness coverage; a matching time
cannot replace the missing proof. All eight controls pass.

One initial preflight rejected an incorrectly checked parent directory before
building. A second attempt compiled the BPF object but rejected generated C
for misleading indentation before attachment. Both failures and their sources
are retained. After correcting those concrete defects, the third attempt
completed the fixed experiment; no capture failure was discarded or retried.

The parent retains the existing private mount namespace, 2 GiB memory,
two-CPU quota, zero swap and 128-task limits. It has a finite 180-second budget,
72 GiB free-space floor, 4 MiB ring, 50,000-record cap per capture and 128 MiB
total retained-file limit. Captures last three seconds; the stimulus is not a
performance benchmark. No global cache reset, kernel fault injection or
production-data modification occurs.

## Independent review and next action

Independent replay verifies all seven retained raw captures and forced-exit
cleanup. Byte/ancestry review checks all 256 actual vector edges; separate
wake-function review checks all 256 waking records and their return/snapshot
bounds. Compiled inputs, generated source, fixture contents and the frozen
reference remain hash-anchored. Global tracing/program state, installed
profile, boot configuration, power setting, quota history and free-space
floor verify. All owned programs detach.

Only [minimal result totals](evidence/stage1-wake-witness.json) are public.
Raw traces, addresses held temporarily in maps, detailed machine records and
per-file hashes remain private. Native early overlap remains open; no
unchanged extension is planned. The next work profiles probe invocation and
execution costs before choosing a concrete reduction. Any profiling facility
needs a documented scope and its own overhead limitations. The full Stage 1
suite and all later accelerator stages remain active.
