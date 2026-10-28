# Stage 1: contemporaneous off/full/compact comparison

The fixed **300-trial** experiment completes with **both full and compact screens failed**. All 200 instrumented captures are retained and independently replayed. One compact capture retains transport, request and vector proof but has an unsupported recorded scheduler order; the frozen reader leaves it unresolved. The complete Linux suite passes 302 tests.

| Condition | Valid blocks / 24 | Full/off overhead | Compact/off overhead | Compact screen |
| --- | ---: | ---: | ---: | --- |
| plain-read | 22 | +1.974% | +0.642% | Fail |
| plain-mmap | 20 | +3.245% | +3.371% | Fail |
| encoded-read | 21 | +2.118% | -1.010% | Pass |
| encoded-mmap | 19 | +3.224% | +1.847% | Fail |

Plain buffered reads fail because the compact capture leaves a scheduler edge unresolved. Plain mapped reads exceed the cost limits. Encoded mapped reads have only 19 valid blocks, below 20 required. Encoded buffered reads pass their scoped absolute screens. No capture is reclassified, block added or old sample pooled to obtain a pass.

| Condition | Compact relative to full | Exploratory 95% interval | Supported direction |
| --- | ---: | ---: | --- |
| plain-read | -1.306% | -3.582% to +0.542% | Unresolved |
| plain-mmap | +0.122% | -2.899% to +3.470% | Unresolved |
| encoded-read | -3.064% | -9.701% to +1.478% | Unresolved |
| encoded-mmap | -1.334% | -4.817% to +1.532% | Unresolved |

Every direct interval spans zero. Fewer records therefore do not establish a faster endpoint. The [minimal public evidence](evidence/stage1-compact-wait-cost.json) retains all per-condition verdicts, intervals and exclusion/failure counts. The earlier full-observer result remains unchanged.

The failure has an actual matched callback and waking record before the recorded nonpreemptive switch-out, followed by wakeup and switch-in. The present reader requires waking inside the outgoing/incoming interval. A new synthetic regression preserves that refusal rather than fabricating a storage-wait duration. Actual kernel handoff semantics and probe timestamp placement need separate source/runtime qualification before a versioned reader change. The frozen cost verdict stays failed.

This is one fixed experiment at four cold selected-worker endpoints. It
compares [full tracing](combined-wait.md), [compact tracing](compact-wait.md)
and no owned tracing in the same blocks. It keeps the earlier
[failed full-observer screen](combined-wait-cost.md) intact and does not pool
its samples. Reduced event volume alone supplies no measured latency gain.

## Design frozen before collection

Each plain/encoded x buffered/mapped condition has three warm-up trials and
24 measured three-arm blocks: 300 launches and 200 instrumented captures in
total. The six possible within-block orders each occur four times, shuffled
with seed 256. Each direct pair occurs in both orders equally often. The
complete schedule, source and qualified binary hashes, equal fixture
contents, limits and freeze timestamps are written and fsynced before timing.

The exact full-qualified and compact-qualified observer binaries are copied
without recompilation. Both qualifications and all three arms use the same
exact inherited-descriptor worker binary. New independently written plain and
encoded 8 MiB fixtures have equal content and verified encoding/no-sharing.
All arms read the same 2 MiB prefix at the unchanged endpoint, which includes
the content hash. File metadata and SSD-internal caches are not claimed cold.

The frozen earlier trial body supplies identical calibration, selected-data
eviction/residency checks, quarter-second quiet interval, endpoint, capture
quality and environmental rules. Only observer startup/reader selection and
the original arm label are dispatched differently. The compact adapter uses
the compact reader and startup, with the same worker handshake. Off trials
must have the original program inventory. Descriptors remain alive until
capture/control-slot completion and observer detach.

## Qualification and comparison rules

Every on capture must pass its strict reader, cover the complete endpoint,
retain actual cold demand and request coverage and resolve its observed
blocked segments through the causal graph. Correct content alone cannot
replace a proof. The compact kind rejects omitted unlock records and marks
unlock counts unavailable. Raw captures and all errors remain visible.

Environmental reasons from any arm exclude the whole three-arm block from
all three ratios. Any capture failure remains independently disqualifying for
the affected scenario's screen, including when the block is also excluded.
Failed warm-ups also disqualify it. Setup, content or lifecycle failures stop
the run and preserve its partial schedule without retry.

Both absolute on/off screens retain the original minimum 20 valid blocks,
3% geometric point limit and 5% upper exploratory 95% interval limit. All four
conditions must pass for a version's complete selected-worker screen to pass.
The direct compact/full ratio is calculated independently from the same
accepted blocks. A wholly negative interval supports lower compact endpoint
time in that condition; an interval spanning zero leaves direction unresolved.
The analysis resamples 5,000 times with seed 256. Independence and general
application overhead remain unproven.

The unchanged environmental limits cover pre-work CPU activity, available
memory, quiet-interval I/O, timed global read/write bounds, recorded CPU
policy and parent throttling. Policy drift within a block excludes all its
arms. Global I/O counters do not identify every unrelated byte, and pre-work
CPU activity is retained as a calculated fraction. Do not interpret accepted
blocks as proof of zero background interference.

The common environment routine includes temperature polling. Upstream
[NVMe hwmon source](https://raw.githubusercontent.com/torvalds/linux/v7.2/drivers/nvme/host/hwmon.c)
fetches the controller's SMART log for temperature input. A deployed-kernel
probe is still needed to establish this target's exact path and wake effect.
Consequently this controlled cost setup supplies no claim about unperturbed
drive idle, confirmed power-state residency or natural wake-up latency.

## Resource and integrity scope

The parent uses 2 GiB memory, no swap, two CPUs' worth of quota, 128 tasks,
a private mount namespace and the existing free-space floor. Its finite
1,800-second runtime budget covers 300 full three-second slots and setup.
Each capture keeps the 4 MiB ring and 50,000-record cap; all retained raw/log
data is capped at 128 MiB. Only counts are written to temporary RAM-backed
progress storage. Traces and results are deferred until collection ends.

All source/binary hashes, fixtures, native reference results, unrelated
program inventory, trace state and drive policy verify afterward. Detailed
environment, trace and integrity records remain local. Public evidence uses
minimal non-identifying result totals. No persistent observer, boot change,
drive-policy change or new storage default is applied by this experiment.
Stage 1 and the full goal remain open; no accelerator gain is claimed.
