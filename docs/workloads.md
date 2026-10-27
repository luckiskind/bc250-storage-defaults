# Stage 1 workload and instrumentation worklist

Status: **in progress; suite not frozen and no Stage 1 speed result yet**.
Stage 0's [starting-environment gate](evidence/stage0-gate.json) passed within its
recorded scope. The full [ten-stage roadmap](DEVELOPMENT_PLAN.md) remains active.
This stage measures system-wide behavior; it does not introduce game-specific
tuning, launch options or a per-title prefetch profile.

## First observed instrumentation limit

The [read-only capability probe](evidence/stage1-trace-features.json) runs on the
current physical kernel and records actual tracepoint field declarations,
offsets, sizes and format hashes. It enables no events and checks that observed
global tracer/clock state stays unchanged. The [fresh opening baseline](evidence/stage1-opening-baseline.json)
records the real device mapping, CPU/GPU memory limits, thermals and policy.

`block_rq_issue` and `block_rq_complete` have device, sector and length fields,
but no shared request identifier in their formatted event payload. Identical
or overlapping sectors, partial completion, merges and requeues make naive
issue/completion pairing ambiguous. Issuing PID/context also does not establish
foreground ownership through asynchronous filesystem work. Do not report a
critical-path latency or foreground stall from these fields alone.

BTF, bpftool, clang and gcc are present. perf, bpftrace and trace-cmd are absent.
Relevant Btrfs/zstd decompression and readahead functions are exposed in the
available function list, but that is not proof of a supported probe ABI or a
successful attachment. The initial observer below validates request identity through the running
kernel's raw tracepoint ABI. Partial completion/requeue handling and
orphan/lost-event interpretation still need broader qualification.
Keep all maps/buffers/time bounded, avoid persistent pins, and preserve unrelated
tracing. Application dependency attribution remains an additional requirement.

## Suite contract to freeze before comparisons

| Domain | Required scenario | Endpoint and state still to qualify |
| --- | --- | --- |
| System/application loading | Representative executable and library loading, plus an interactive application | Usable-state marker; fixed package tree and CPU/GPU policy |
| Game loading | Representative installed titles and distinct asset formats | Repeatable menu/scene marker; fixed runtime/shader/save state |
| Asset streaming | Reproducible traversal or replay with frame-time capture | Fixed route/replay, streaming interval and long-frame events |
| Controls | Compressible and already compressed/incompressible data | Distinguish storage, decompression and memory/cache limits |

An earlier PRAGMATA title-screen procedure exists privately, but its old results
are not promoted into this new frozen suite. Its title-screen endpoint is not
an asset-streaming benchmark. Audit the installed workload inventory, backups
and usable-state markers before choosing the final suite or aggregate weights.

For each workload, freeze input hashes, version, endpoint definition, timeouts,
launch/stop procedure, background activity rules, cache state and run ordering.
Distinguish asset-cold/runtime-warm from a cold system boot and warm repeated
execution. Verify residency where supported; do not label cache eviction as
SSD power-state evidence. Avoid a global page-cache reset on the working OS.

Power-only B0/B1 comparisons must use equivalent resets of the same frozen
layout. B1/B2 compare independently verified copies; incidental allocation
differences must be recorded. Account for loop/outer-filesystem effects when
using the prepared userspace images. Keep physical conversion writes, metadata
growth and lost sharing separate from logical maintenance budget charges.

## Remaining Stage 1 work

1. Freeze the concrete workload matrix, weights and regression thresholds from
   the roadmap; validate usable-state/frame markers and cache conditions.
2. Add the versioned runner and anonymized event/result schema under `bench/`,
   with interfering activity, environment drift and run order recorded.
3. Qualify request timing, queue/merge/requeue behavior, faults, filesystem reads,
   readahead and decompression attribution where the actual ABI supports them.
4. Measure tracing overhead against uninstrumented trials before relying on
   instrumented results. An event-format inventory measures no overhead.
5. Run controlled B0/B1/B2 trials and build `analysis/` reports with uncertainty,
   storage-critical waiting and alternative CPU/RAM/GPU bottlenecks separated.

The stage gate remains open. No accelerator architecture is selected from the
feature inventory, historical synthetic throughput or an ambiguous disk trace.

## Initial request-identity qualification

The [temporary request observer](request-tracing.md) now passes five bounded cases on the real kernel: idle, 2,048 serial reads, 8,192 overlapping same-location reads, an explicitly incomplete cap, and cleanup after forced exit. Known-read counts and bytes match exactly with no ring loss; fixture residency remains zero before/after the accepted controls. This supplies request-identity evidence rather than sector matching. The first control failure is retained and documented. Tracing overhead, partial/requeue/error paths, foreground dependency attribution and the frozen application matrix remain open.

## Frozen observer overhead screen

The [two-batch calibration](trace-overhead.md) retains all 86 trials and fails the prespecified serial-read screen. The fixed extension estimates +4.460% elapsed-time overhead (exploratory 95% interval +2.191% to +6.706%); three whole-window capture flags also remain disqualifying. Read bytes match and ring loss is zero, so those flags are not presented as proven read transport loss. The concurrent pilot control alone passes. Keep the observer opt-in, preserve these separate batches, qualify a distinct batched-consumption variant and compare it under a new frozen contract. No accelerator improvement or Stage 1 gate pass follows from this measurement. The Linux suite now passes 127 tests.

## Batched observer decision

The [distinct batching variant](batched-tracing.md) passes seven transport checks, including early final drain and visible ring overflow. Its 75-trial blocked comparison on one physical fixture shows no demonstrated overhead benefit and has only 18 valid blocks, below the frozen 20. Preserve the negative decision. Qualify the zero-byte/flush lifecycle and measure probe cost before another observer change, while freezing concrete application workloads and endpoints. No existing strict verdict is retroactively changed.

## Application selection and first operational endpoint

The [workload endpoint record](workload-endpoints.md) now pins installed application/game versions and observed asset suffixes, plus a tentative seven-scenario mix before new performance comparisons. The complete suite is still unfrozen. Three final-source Konsole launches each receive a valid cursor reply through the owned child's PTY and close normally; this qualifies a terminal operational marker, not first composited frame, cold-cache state or acceleration. An offline audit of all five strict failed comparison windows finds 11 flagged zero-byte flush records and no flagged reads. The 11 unmatched completion callbacks still lack operation/cause attribution, so existing verdicts remain unchanged. The Linux suite passes 134 tests.
