# Stage 1: native task-local context capability

The separate capability diagnostic passes **11 native controls** and all
**335 Linux tests**. Six positive cases create and explicitly delete **4,299
contexts**. All **17,185 scheduler observations** agree with the independent
hash-map oracle. Typed scheduler hooks can use task storage on this kernel.

This is a feature/lifecycle qualification. It does **not** qualify a replacement
causal observer, a lower observer cost or an accelerator gain. The existing
[handoff observer](handoff-wait.md), [profiling result](probe-cost.md) and all
historical cost failures remain unchanged. Nothing is promoted to a default.

| Case | Context entries / returns | Selected threads | Largest active ledger | Scheduler observations |
| --- | ---: | ---: | ---: | ---: |
| Plain buffered | 16 / 16 | 1 | 1 | 64 |
| Plain mapped | 4,095 / 4,095 | 1 | 1 | 16,374 |
| Encoded buffered | 30 / 30 | 1 | 1 | 111 |
| Encoded mapped | 128 / 128 | 1 | 1 | 512 |
| Two-thread buffered | 28 / 28 | 2 | 2 | 112 |
| Two-thread held marker | 2 / 2 | 2 | 2 | 12 |

## What the feature proves

Six temporary programs observe `io_schedule` entry/return, typed
`sched_switch`, `sched_waking`, `sched_wakeup`, and a test-only syscall marker.
Actual deployed BTF signatures are checked before compilation and attachment.
The verifier accepts current-task and typed scheduler arguments for task-storage
access. This does not establish support for untyped queued-owner pointers.

Each context gets an anonymous generation and task token. The task-local
record is compared against an independent expected-context hash record at
every observed scheduler lookup. The two-thread controls retain both identities;
one cached task pointer cannot stand in for another selected thread.

Creating, active and closing phases distinguish publication/cleanup transitions.
Entry and observation-completion clocks bound each feature record. These
brackets can overlap publication/return boundaries; they are not exact point
ordering or a replacement for the causal observer's timestamp contract.
The feature exports no task/thread IDs or addresses.

The five I/O cases retain the complete 2 MiB demand on every pass, eight
passes per thread, independent content hashes and strict zero-resident checks.
Private per-thread files prevent one thread's eviction from changing the
other's cache control. The held-marker case uses read-only process-query
syscalls to create two contexts, holds both at a barrier, and then deletes
them. It proves coexistence, not storage waiting or every SMP interleaving.

## Exit and pending-context accounting

Task-storage `get_next_key` returns unsupported (errno 524) on this kernel.
Do not use an unsuccessful enumeration as evidence of an empty map. The
feature retains the independent expected-context hash and explicit creation/
deletion ledger.

Killing a worker while two marker contexts are held leaves **two entries,
zero returns and two unfinished expected contexts**. Transport completes, but
context quality fails. Task exit does not manufacture a successful close.
This does not directly measure the kernel's eventual storage-memory release.

Other controls verify creation omission, an empty no-slot case, a two-record
cap and forced observer exit. Omission leaves the expected lifecycles visible
and fails storage proof. Cap and worker-exit cases remain incomplete; forced
observer exit proves owned-hook cleanup without claiming context completion.

## Preserved failures and cache repair

The first build rejected generated-header declarations and a helper name that
collided with a kernel typedef, before attachment. Scoped generated-header
diagnostic handling and a distinct helper name repaired the compilation.

The next attempt passed its plain buffered case, then the repeated mapped
worker exited during cache verification. Its completed first case and failure
record are retained; the failed mapped case has no complete raw capture.
A separate run without BPF reproduced a failed zero-resident check on pass
six, with 214 resident pages. The exact transient page owner was not traced.
A read-ahead/reset interaction is an inference, not a proven historical cause.

Adding `MADV_RANDOM` to the private mapping preserves the full 2 MiB demand
and passes eight strict cold checks in the uninstrumented diagnostic, then
the final native qualification. No cache check is weakened. This is a changed
capability stimulus, not a speed comparison or production application tweak.

Individual cold faults increase record volume. The final feature uses a
4 MiB ring and 32,768-record cap instead of its initial 1 MiB/8,192 design.
The unchanged parent limits remain 2 GiB memory, zero swap, two CPUs' quota,
128 tasks, a private mount namespace, 180 seconds, a 72 GiB free-space floor
and 128 MiB retained files. The larger capture budget is not transferred to
the existing observer or any cost claim.

## Independent review and next gate

Ten retained raw captures replay exactly; forced observer exit is checked
separately. Independent context grouping checks generations, task tokens,
clock brackets, creation/deletion partitions and content/cold-pass results.
All positive oracle comparisons match. The frozen reference sources and
binaries, installed profile, boot configuration, power setting, quota history
and free-space floor verify. All owned programs detach.

Only [minimal capability totals](evidence/stage1-task-context.json) are public.
Detailed machine records, raw traces and fixture hashes remain private.

Next, replace only scheduler-side context lookup in a separate observer
revision. Preserve the existing hash bridge for queued callback owners,
independent pending accounting and every request/vector/folio proof. Add a
full-observer two-thread case, requalify all existing negatives and timing
semantics, then freeze a contemporaneous cost comparison. Capability alone
does not establish correctness or benefit of that replacement. The complete
Stage 1 workload/application gates and ten-stage goal remain active.
