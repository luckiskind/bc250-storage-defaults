# Stage 1 v2 observer overhead calibration

This fixed experiment compares tracing off with the separately
[qualified lifecycle-aware v2 observer](trace-v2.md). It measures the observer's
effect on two synthetic read controls. It does not measure an accelerator
benefit, prove application overhead or pass the complete Stage 1 gate.

## Contract frozen before collection

`bench/measure_trace_v2_overhead.py` freezes 24 paired comparisons per scenario,
with 12 off-first and 12 v2-first orientations shuffled using seed 253. Each
scenario begins with one warmup pair. There are 100 trials in total: four
warmups and 96 measured trials. Scenarios are analyzed separately:

| Scenario | Dedicated worker |
| --- | --- |
| Serial strided reads | One reader, 8,192 aligned 4 KiB reads / 32 MiB |
| Concurrent same-location reads | Four readers, 2,048 aligned 4 KiB reads each / 32 MiB total |

Every trial uses the same new physical 64 MiB NOCOW regular fixture and the
original worker binary. The fixture copies the original protected control's
content without reflinks, sparse ranges or encoded extents. Its content and
the original remain verified after collection. All conditions have targeted
fixture-data eviction, zero residency checks and prefaulted direct-I/O buffers.
No global cache reset or drive-policy change occurs. SSD internal caches and
the rest of the system are not asserted cold.

The full order, source/binary/fixture hashes, qualification references, limits
and criteria are saved before timing starts. The contract file is fsynced.
Progress output, traces, logs and result files are deferred until collection
ends, so that output does not produce later-trial writeback. Existing host
activity remains observable and is subject to the exclusions below.

## Endpoint and quality rules

The endpoint is the unchanged worker's barrier-to-join monotonic elapsed time.
Observer startup, result serialization and the approximately two-second condition
slot are outside this endpoint. Process CPU costs are retained separately;
observer-process CPU excludes some kernel callback cost and cannot represent
the total instrumentation cost by itself.

The original numerical limits remain: at least 20 valid pairs per scenario,
geometric overhead no more than 3%, and an exploratory paired 95% upper interval
no more than 5%. Resampling uses the existing estimator and 5,000 draws, without
pooling historical batches or the two scenarios. The intervals do not establish
independent samples or application effects.

An instrumented trial requires the new v2 stream's native-qualified provenance
checks. Unknown requests, errors, loss, contradictions and unclosed contexts
remain disqualifying. Raw flags and proven auxiliary events stay visible.
Every dedicated window must contain exactly 8,192 ordinary read records and
32 MiB completed, and the complete worker interval must lie within collection.
This prospectively uses v2's explicit proof rather than rewriting old v1 failures.

Environmental exclusions remove a complete pair: preceding CPU activity above
10%, preceding device activity above 128 KiB, additional worker-window device
traffic above 128 KiB, available memory below 2 GiB, CPU policy drift, or observed
cgroup CPU throttling. Policy is compared within trials and across each pair.
The 5000 us drive policy must verify before/after each worker and across the run.
Any failed capture, even in an environmentally excluded pair, prevents a pass.
Warmup capture failures also remain disqualifying; warmup durations are never
used in the estimates. The analyzer refuses missing/duplicate conditions,
missing entire planned pairs and missing scenarios.

## Result

| Scenario | Valid pairs | Geometric overhead | Exploratory paired 95% interval | Frozen control screen |
| --- | ---: | ---: | ---: | --- |
| Serial strided reads | 22 / 24 | +0.389% | -1.677% to +2.475% | Pass |
| Concurrent same-location reads | 23 / 24 | +2.052% | -0.796% to +4.267% | Pass |

**Decision: v2 passes this two-scenario synthetic control screen.** Both minimum
sample counts and point/upper-interval limits are met. All 50 instrumented
trials, including warmups, pass stream quality and account for the exact known
read window. Three proven internal device flushes and three proven software
sequences remain visible, including their raw flags; no unresolved record or
unknown completion is accepted. No measured or warmup capture fails. This is not a comparison of
v2 with a historical observer or evidence of a loading/streaming speed gain.

Serial pair 6 is excluded for additional device I/O; serial pair 21 and
concurrent pair 10 are excluded for preceding device activity. These exclusions
retain both conditions and all their quality records. The detailed
[aggregate evidence](evidence/stage1-trace-v2-overhead.json) contains all 100
timing rows, the frozen order, every exclusion and each instrumented trial's
provenance/counter totals. The single collection is retained without extension,
an unchanged repeat or historical pooling.

No worker-window cgroup CPU throttling is observed, and CPU policy is constant
across all recorded before/after snapshots. Qualified binaries, the original
worker and both fixture contents verify. All owned programs disappear; global
trace state and unrelated program inventory remain unchanged. The live seven
installed files, boot configuration, 5000 us power policy, enabled power/timer
services and previous quota charges verify after collection. The Linux suite
passes 200 tests.

## Resource and interpretation limits

The parent runs in a private mount namespace with two CPU equivalents, 2 GiB
memory, 1.5 GiB memory-high threshold, zero swap, 128 tasks and five minutes.
The original v2 map/ring/event bounds remain. The 72 GiB host free-space floor
is preserved. Copied fixtures, retained traces/builds and earlier artifacts add
lab writes/space; they neither reset nor expand production maintenance quotas
or quantify physical NAND writes.

The run must verify fixture contents, qualified source/binaries, removal of
all owned programs, unchanged global tracing/unrelated program inventory, and
the working drive policy. The original released profile and old observer
experiments remain unchanged. This is an opt-in calibration, never a persistent
tracing service.

This result qualifies the synthetic control screen on this machine,
kernel and resource budget. Real application/wrapper cost, broader callback
order/fault coverage, input/cache closure, remaining workload endpoints and
foreground dependency attribution remain separate gates.

```sh
sudo python3 bench/measure_trace_v2_overhead.py run \
  --qualified /absolute/private-lab/passing-v2-qualification \
  --original /absolute/private-lab/original-passing-qualification \
  --output /absolute/private-lab/new-v2-overhead-calibration
```

Existing outputs are refused. Raw captures and detailed snapshots remain
private; reviewed aggregate evidence must retain every trial and exclusion.
