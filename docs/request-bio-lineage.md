# Stage 1: request generations and issue-time bio members

Status: the separate 24-program diagnostic passes **14 native controls**.
Nine positive cases account for **97 request generations**, **143 selected bio
members**, four multi-bio requests and six changed-generation address reuses.
It adds actual issue-time membership to the qualified
[physical-bio bridge](physical-bio-lineage.md). Its output is a causal object
graph for selected file reads, not a whole-application critical path or a new
accelerator speed result. The ten-stage goal and Stage 1 remain open.

## Keep each reference intact

The new BPF source includes the frozen physical-bio source, which includes the
frozen [logical read reference](read-lineage.md). A checked loader derivation
disables the old physical completion program and adds request issue, requeue
and completion programs, for **24 active programs**. The previous physical,
[folio-wake](folio-wait-lineage.md) and [request v2](trace-v2.md) sources,
binaries, raw formats and results remain unchanged. Their cost or coverage
qualifications are not transferred to this observer.

The runner verifies both logical and physical reference source/binary hashes,
checks 16 actual BTF function/callback signatures, and freezes extension source,
generated loader, compiled binaries and BTF-header hashes before collection.
The new `bc250-request-bio-diagnostic` kind has its own
[structural schema](../bench/request-bio-lineage.schema.json) and strict graph
reader. It projects only the unchanged lower stages into their reference
readers after checking combined transport accounting.

## Identity at issue

Request identity is the actual request object paired with a nonzero
`start_time_ns` generation in private maps. Only anonymous IDs are exported.
At issue, the observer walks the actual complete `request.bio` chain, with a
64-member limit. It requires the sum of live bio sizes to equal the request's
data length. A request enters the selected graph only if at least one actual
bio object matches a live selected physical bio. PID, sector and time proximity
never supply ownership.

Every member of a selected request receives a snapshot, including members
without selected ownership. Selected members bind to their physical bio ID and
exact size/offset; unselected members have an explicit zero physical ID. The
request's total bytes are therefore kept separate from selected bytes. A
request with multiple members proves their composition at issue; it does not
by itself establish how, where or when a preceding merge happened.

Chain scans and member verification use the kernel's `bpf_loop` helper with
the same explicit 64-iteration limit. This avoids verifier state explosion
without reducing the inspected bound. A second pass must agree with the first
on member count, selected count and bytes. A truncated or inconsistent chain
fails quality even when its unseen suffix cannot be classified as unrelated.

## Completion prefixes and requeues

Raw request completion runs before the kernel advances or frees its current
bio prefix. Every completed member must match the saved request generation,
anonymous request ID, actual bio object and remaining size. The reader enforces
the same issue-time member order, so a completion cannot skip a live prefix.
Partial member chunks preserve the remaining membership. Only full reporting
of a selected member emits the lower physical completion record and closes its
temporary physical context. A final request record requires all issued bytes
and members to be accounted for.

A requeue records the remaining request bytes and moves it out of the issued
state. Reissue requires the same generation, remaining membership and bytes,
and increments the issue count. Completion during the requeued state,
unexplained repeated issue, changed members, missing contexts, errors and map
failures are explicit failures. An atomic busy claim rejects overlapping
callbacks for one tracked request; it does not silently race mutable state.
Broader native partial, requeue and concurrent callback behavior still requires
independent controls.

A separate bounded history map remembers previously selected request addresses,
their private generations and anonymous IDs. Reuse needs a changed generation
and an already closed old context. An anonymous reuse-proof edge connects the
new request to that closed old ID. Same-generation reuse, overlapping old
lifetimes and a full history map fail quality. The map is a lifetime registry,
not a pending I/O context, and is never pinned or exported.

The source background is upstream Linux's
[request issue and completion implementation](https://raw.githubusercontent.com/torvalds/linux/v7.2/block/blk-mq.c).
The installed kernel's actual BTF, successful loads and native controls define
the qualification scope. Source similarity or available symbols alone do not
prove runtime coverage.

## Native control design

The existing plain/compressed × buffered/mapped × cold/warm matrix retains the
original 2 MiB read and content hash. Private callback calibration runs before
selection; the target's measured cold/warm state is re-established afterward.
Same-inode/different-open, record cap, forced exit and missing callback proof
remain controls. A new issue-proof-disabled case must retain correct worker
bytes while leaving physical bios without request membership and failing
graph quality.

The additional serialized reuse worker reads a private 2 MiB prefix eight
times. Before every pass it evicts only its own 8 MiB fixture and verifies zero
resident file pages with privileged `mincore`. It hashes every pass and requires
the same bytes. Twenty-millisecond pauses allow completed requests to recycle;
the worker alone is pinned to one CPU from its inherited allowed set. This is
a functional identity control, not a performance benchmark. It changes no
system affinity, scheduler, queue or power setting.

The parent retains the 2 GiB memory, 200% CPU, no-swap, 128-task and 300-second
bounds, private mount namespace and 72 GiB host free-space floor. Nine context
maps and the separate history registry each hold at most 4096 entries. The
ring remains 4 MiB, captures three seconds and saves at most 50,000 records.
All owned programs detach before saved output is written. Raw kernel addresses,
task IDs and generation values remain in temporary private maps.

## Counter and protocol meaning

Stages 1–16 retain the physical observer's meanings. New stages are issue (17),
ordered member snapshot (18), requeue (19), reissue (20), completion chunk (21),
request end (22), and changed-generation address reuse (23). Physical final
records are full block-layer byte reports, not a census of `bio_endio` callbacks
or hardware service-time measurements.

Request counters 0–6 count new selected requests, issues including reissues,
closed selected requests, selected members, all members, requeues and partial
member chunks. Counter 16 counts changed-generation reuse edges. Those counts
must match the saved graph exactly. Error counters are issue proof absent (7),
zero generation (8), truncated/invalid walk (9), map failure (10), identity or
membership inconsistency (11), lifecycle conflict (12), reported status error
(13), completion without selected issue proof (14), concurrent callback conflict
(15), same-generation recycled address (17), and history insertion failure (18).
Counters 19–23 are reserved and must be zero. Transport loss, malformed records,
remaining contexts, unknown edges and mismatched counts also fail quality.

## Observed result and retained attempts

The [reviewed evidence](evidence/stage1-request-bio-lineage.json) retains all five
attempts. The first rejects a compiler-optimized pointer OR in the verifier;
the second exceeds verifier complexity. Neither releases the worker. A bounded
loop precursor passes 13 controls and establishes native multi-bio composition.
The next attempt rejects repeat-worker indentation warnings at compile time.
Only the final source, with its 24 counters and history registry, supplies the
14-control result below. Earlier outcomes are not pooled into it.

| Case | Request generations | Selected members | Multi-bio requests | Changed-generation reuses | Selected reported bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain-read-cold | 8 | 8 | 0 | 0 | 2097152 |
| plain-read-warm | 0 | 0 | 0 | 0 | 0 |
| plain-mmap-cold | 18 | 19 | 1 | 0 | 4194304 |
| plain-mmap-warm | 0 | 0 | 0 | 0 | 0 |
| compressed-read-cold | 1 | 16 | 1 | 0 | 196608 |
| compressed-read-warm | 0 | 0 | 0 | 0 | 0 |
| compressed-mmap-cold | 2 | 32 | 2 | 0 | 393216 |
| compressed-mmap-warm | 0 | 0 | 0 | 0 | 0 |
| serialized-cold-reuse | 68 | 68 | 0 | 6 | 16777216 |

The final source observes up to **21 members in one request**. All selected
member bytes equal the lower physical completion reports: **23,658,496 bytes**
across the nine positive controls. The reuse worker separately verifies eight
cold passes and all content hashes, observes 68 request generations and six
recycling edges, and leaves every context closed. No positive stream has a
transport loss, error counter or unknown request edge. Warm cases issue no
selected data requests. These are functional accounting results, not storage
latency or throughput improvements.

The wrong-open-description control emits no selected events. The four-record
cap remains explicitly incomplete. Forced exit removes all 24 programs.
Disabling callback proof leaves originals uncovered; disabling issue proof
preserves correct worker bytes but leaves physical bios without matching issued
requests and fails quality. Every negative is retained rather than waived.

Independent review re-parses all 13 saved raw streams and separately checks
immutable issue snapshots, flattened completion-prefix byte positions, physical
member sizes and closed-generation recycling edges. Source, generated loader,
compiled worker/observer, BTF header, fixture and both reference hashes match
after collection. All seven installed profile files, boot configuration,
5000 us policy, existing quota history and active/enabled power/timer verify.
The full Linux suite passes **257 tests**, plus syntax, warning-clean native
worker compilation and invalid-input guards. CI also builds the new worker.

Native multi-bio membership and changed-generation recycling are exercised.
Native mixed selected/unselected requests, partial member completion and
requeue/reissue are **not** exercised by these controls; their synthetic graph
tests do not change that verdict. Merge history and whole-application waiting
remain unqualified.

## Remaining development gates

Native mixed selected/unselected membership, requeue/partial/error paths,
cross-chunk and mirrored reads, merge history, broader recycling/interleavings,
and queue insertion/wait accounting remain separate qualifications. Unit graphs
cover some of those cases but are not native evidence. The folio-wake result
still uses a separate observer: combining both graphs needs a new protocol and
qualification, followed by a measured total tracing-cost screen. Whole
application critical paths, input/cache closure and the frozen workload suite
remain incomplete. No additional system default is promoted from these tests.
Suspend/wake remains excluded because the owner confirms it is unsupported.
