# Stage 1 lifecycle-aware request observer v2

Status: ten native controls pass, including two deliberate proof-removal cases.
The separate v2 protocol distinguishes ordinary device I/O, a positively
identified internal device flush, and an identity-tracked zero-payload software
sequence. The later [fixed calibration](trace-v2-overhead.md) passes two synthetic overhead
control screens. Application overhead, foreground attribution and broader
fault/concurrency paths remain unqualified. It is opt-in development instrumentation, never an installed
service or a demonstrated accelerator improvement. Stage 1 remains open.

## Why this is a new protocol

The [native lifecycle investigation](request-lifecycle.md) demonstrated that
device flushes and software sequences can use different request identities and
callback paths. The [shared-lookup timing experiment](shared-disk-tracing.md)
then retained failed v1 capture screens despite exact worker read accounting.
Neither result authorizes relabeling an arbitrary zero-byte request as benign.

V2 keeps the v1 source, binaries, schema and historical verdicts unchanged. It
has its own [structural schema](../bench/request-trace-v2.schema.json), native
loader and independent [semantic reader](../analysis/request_trace_v2.py).
The reader requires cross-field identity/provenance, lifecycle, loss and counter
checks beyond the JSON structure. A v1 capture cannot silently become v2.

Raw flags remain in every event. In particular, missing-insertion/zero-byte
information is retained even for a proven auxiliary record. V2 reports both
the raw flagged-record count and unresolved records. Only positively proven
auxiliary cases can pass the new scoped quality check; this is a prospective
protocol change validated on new controls, not a repair of old measurements.

## Identity and proof

All ordinary operations remain in scope. The request key combines its address
with a nonzero allocation timestamp inside a bounded private BPF map. Published
identities are anonymous per-observer sequences. Ordinary insertion, issue,
requeue, partial/error and completion flags remain explicit. The cached disk
pointer traversal avoids duplicated checked CO-RE reads. Timing markers are
monotonic observations within callbacks, including observer/kernel effects;
no device-latency equivalence to v1 or pure hardware service-time claim follows.

An internal device flush requires operation 2, zero payload, no bio and a
positive comparison of the actual request pointer with the hardware queue's
internal flush request. Its completion must also be observed. A negative pointer
comparison or a zero byte count alone cannot establish this class.

A software sequence requires an observed zero-payload operation-1 entry into
`blk_insert_flush` with the original preflush bit, its consumed=true return,
and completion of the same allocation identity. The running kernel's BTF verifies
the entry/return and raw block callback signatures; local encoding checks pin
operation values and the preflush bit. The earlier
[upstream flush source](https://github.com/torvalds/linux/blob/v7.2/block/blk-flush.c)
supplies background context, not an assumption that the modified kernel is
identical to upstream. Native probes establish this limited target behavior.

Entry saves the generation in a second map keyed by request address and current
task identity. Return looks up that saved context and never dereferences the
returned request. This avoids relying on potentially freed/reused request fields
after the function body. Context collisions/map failures remain errors. Addresses,
allocation timestamps and task IDs never appear in the output; no sectors,
filenames or process names are exported. All map objects are temporary and
un-pinned.

Completion and return can arrive in either order. Each writer owns separate
payload fields and publishes a ready bit using the shared atomic helper in
`bench/trace2_protocol.h`. Only the writer that closes the complete pair can
publish. Duplicate/contradictory observations increment an error counter.
A false return produces an explicitly unresolved record; missing entry/return
proof, unknown completions and unfinished contexts prevent a quality pass.
Software intervals are never included in ordinary device request timing sums.

## Native qualification

The final fixed suite uses one new 64 MiB NOCOW regular file. It runs on the
BC-250's existing kernel, with the physical device used only as the observation
filter. Aligned direct reads use prefaulted buffers. The synchronization cases
each update eight 4 KiB ranges and call fdatasync on that private file only.

| Case | Observed result |
| --- | --- |
| Serial read | Exactly 2,048 worker reads / 8 MiB; 2,048 records; zero resident fixture data |
| Four same-location readers | Exactly 8,192 worker reads / 32 MiB and 8,192 full-capture records; zero resident fixture data |
| First synchronization sequence | 8 proven internal flushes and 8 proven software sequences; zero unresolved/orphan/censored contexts |
| Software proof disabled | 8 unmatched completions remain visible; zero proven software sequences; quality correctly fails |
| Internal proof disabled | 8 unresolved records remain visible; 8 software sequences still proven; quality correctly fails |
| Second synchronization sequence | Same two sets of 8 proven auxiliary records; zero unresolved/orphan/censored contexts |
| Deliberate 16-record cap | Incomplete transport stays explicit; known reads present |
| Early interrupt | All 8 reads / 32 KiB drain; interruption stays explicitly incomplete |
| Stalled consumer | Ring overflow remains explicitly lost/incomplete; 47,662 records retained |
| Forced observer termination | All six owned programs disappear after SIGKILL |

“Pass” for a negative, capped or interrupted case means correct rejection or
visible loss, not a usable performance capture. Background traffic is retained
and not assigned to the foreground merely because its timing overlaps a case.
The [aggregate evidence](evidence/stage1-trace-v2.json) records every case,
counter, source/build hash and scope; raw captures stay private.

The initial implementation also passed these functional controls at smaller
256/1,024-read sizes on an 8 MiB fixture. That artifact is retained separately.
The final suite expands to the original observer's 2,048/8,192-request sizes
and 64 MiB fixture. A second expanded run passed before the final runner added
explicit read/write operation and mask-width guards. The final guarded run above
also passes; all three artifacts remain separate. These are implementation/
compatibility controls, not pooled or selected performance repeats.

## Atomic publication and interpretation checks

The exact atomic ready/close helper is compiled into a separate native C
control. Both serial orders pass; duplicate and invalid ready bits refuse.
Two threads exercise 10,000 concurrent publication pairs with zero failures and
exactly one publication per pair. CI builds and runs this helper too.

This is a host control of the shared algorithm, not proof of every kernel BPF
interleaving or JIT behavior. The native flush captures in this qualification
all complete after function return. Completion-before-return in the actual
kernel callback program remains unexercised. Request reuse/recursive return
contexts, arbitrary capture boundaries, injected device errors, partial
completions and requeues remain broader qualification work.

Twelve Python counterexample tests reject missing proof, zero-byte reads,
unproven device flushes, disabled-tracking claims, false returns, hidden errors,
orphans/unfinished contexts, hidden loss, impossible lifecycle counters, private
fields, Boolean integers, reused identities and out-of-lifetime events. They
also accept completion-before-return only after valid entry, keep tail events
bounded by actual detachment and refuse silent v1 promotion. The full isolated
Linux suite passes 195 tests. A structural JSON schema accompanies these
mandatory semantic checks; it is not a substitute for them.

## Bounds, health and next gate

The qualification job uses a private mount namespace, two CPU equivalents,
2 GiB memory, zero swap, 128 tasks and a five-minute lifetime. Each of the two
private identity/context maps has 8,192 entries, the ring has 4 MiB and the
saved-record cap is 200,000. The 72 GiB host free-space floor remains. Retained
fixtures, earlier attempts, builds and logs add lab writes/space; they do not
reset or expand production maintenance quotas or measure physical NAND writes.

No raw-device flush ioctl, global cache reset, formatting, boot/drive-policy
change or persistent hook is introduced. Global trace settings and unrelated
program inventory verify unchanged; all six owned programs detach. The original
v1 source/binaries, seven live installed files, boot configuration, 5000 us power
setting, enabled power/timer services and quota history verify after the run.

The later [100-trial calibration](trace-v2-overhead.md) now passes its two
synthetic overhead screens with unknown events, loss and unclosed contexts
still disqualifying. Next measure application/wrapper cost, extend native
ordering/fault coverage, and correlate filesystem/page-fault/decompression
activity with real workload endpoints. No application throughput gain or
architecture promotion follows from these measurement controls.

```sh
sudo python3 bench/qualify_trace_v2.py run \
  --output /absolute/private-lab/new-v2-qualification
```

Existing output directories are refused and failures retained. The structural
schema uses exact unsigned 64-bit integer clocks; consumers must preserve them
without rounding.


The [native application capture integration](application-trace-v2.md) now
passes one cold and one warm Konsole launch with the unchanged selected-input
fixture and endpoint. Both whole-device captures cover the full trials and pass
stream quality, including 17 proven internal flushes and 17 proven software
sequences. No loss, unresolved context or remaining owned process is accepted.
The suite passes 207 Linux tests; application overhead and foreground
critical-path attribution remain open. No accelerator gain is claimed.

The [selected-file Btrfs lineage diagnostic](read-lineage.md) passes 11 controls on the actual kernel: buffered/mmap cold/warm paths, a same-inode wrong-open-description rejection, explicit cap incompleteness and forced-exit cleanup. The final source captures fault-around that an earlier attempt missed, links 54 original bios and 48 zstd spans, and retains every attempt. Exact folio wait/request dependencies and this diagnostic's overhead remain unqualified. The suite passes 225 Linux tests; no accelerator gain or default promotion is claimed.
