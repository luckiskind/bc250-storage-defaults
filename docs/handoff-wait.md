# Stage 1: scheduler-entry timestamps and early-wake classification

The separate v2 handoff diagnostic passes **16 native controls** with 28
owned probes. All **313 Linux tests** pass. Nine positive cases account for
106 request generations, 147 selected members, 23 changed-generation address
reuses and 23,658,496 reported physical-input bytes. All 14 observed blocked
segments resolve through actual request/vector/queued-folio proof.

**No early-wake handoff occurred in these native captures.** The new
classification has synthetic coverage, while independent native overlap
witnessing, broader scheduler interleavings, total diagnostic cost and
whole-application critical paths remain unqualified. This is no accelerator
gain or default promotion. The [300-trial cost failure](compact-wait-cost.md)
and every earlier reader/result stay unchanged.

## Why a separate revision

The earlier compact capture retained request and vector proof but recorded
waking before switch-out. Its unchanged reader correctly refuses that order.
A private read-only audit identifies the installed kernel image with the
running kernel's GNU build ID. Manual control-flow review and actual task
field offsets establish that its waking trace path precedes run-queue/on-CPU
checks. The installed header distinguishes wake initiation from actual wakeup.

[Upstream scheduler source](https://raw.githubusercontent.com/torvalds/linux/v7.2/kernel/sched/core.c)
also places waking before the on-CPU handshake and switch tracing before the
context switch. This supports the possibility of early wake initiation;
it does not identify the dynamic branch taken in the failed capture.

The old probes read clocks after selection/proof work. Cross-CPU emission
times therefore cannot identify exact hook-entry order. Version 2 records
one clock at each scheduler hook's entry, before selection/map work, and
passes the same clock to both sides of a switch. The three compiled scheduler
programs independently verify one clock helper, before other helper calls.
These are hook-entry clocks, not exact machine context-switch instants.

Callback and vector timestamps retain their original proof-completion
semantics. Vector scanning is not moved after the wake, nor is a finished
proof backdated to callback entry. The inherited worker binary is unchanged.

## Reader rules and duration meaning

The v2 protocol requires `scheduler_timestamp_basis: "hook-entry-v1"`, its own
kind/schema version and explicit omitted unlock counts. The loader/readers
reject the older protocol. Checked generation retains all request/vector
proof work and omits the same optional unlock hook as the compact reference.

The reader assigns waking/wakeup records across each active sleep slot and
uses each scheduler record at most once. Exact slot/callback identity,
successful queued-folio proof, preceding physical request reports, actual
vector overlap and a unique wakeup remain mandatory. Missing, duplicate,
unrelated, reused or ambiguous-clock wake evidence stays unresolved.

For an ordinary order (out, matched callback/waking, wakeup, in), it reports
the existing observed blocked/delivery/runnable partition. For an early
order (matched callback/waking, out, wakeup, in), it reports an explicit
handoff category, off-CPU interval and the delivery overlap from out to
wakeup. `early_wake_storage_blocked_ns` is null, and complete storage-blocked
interval accounting is false. The normal blocked-time union then covers
only the separately counted ordinary segments; its zero for an early-only
sample does not mean zero hardware waiting. Wakeup-before-out and equal
scheduler timestamps remain unsupported.

These selected-worker object dependencies are not minimal device service
time or a whole-application critical path. A callback may return after the
task resumes; the reader keeps this case without dereferencing a freed wait
entry. Early wake classification alone supplies no native timing claim.

## Qualification and preserved limits

The fixed functional harness retains four cold, four warm and one serialized
cold-reuse positive case, wrong-open identity, cap and forced-exit controls,
and callback/issue/folio/vector proof removal. All 16 pass on the first
attempt. No experiment was extended to seek an early order.

Independent replay verifies every retained capture against the new reader,
source/generated/binary hashes, frozen reference qualifications, actual byte
partitions and request/vector ancestry. All 14 ordinary blocked segments have
a consistent non-overlapping duration partition. Unrelated tracing inventory,
the power policy, seven installed hashes, boot configuration, quota history
and free-space floor verify. All owned hooks detach; no persistent pin or
system-wide tracer is installed.

The [minimal evidence summary](evidence/stage1-handoff-wait.json) contains
only reviewed totals. Detailed image/hash records, raw traces and disassembly
remain private. Large/partial folios, mixed request ownership, partial/error/
requeue paths and native early-wake interleavings remain open. New ordinary
functional qualification does not establish observer cost. An independently
witnessed native early handoff and probe-cost profiling are the next gates,
before another changed, frozen comparison or application attribution.
