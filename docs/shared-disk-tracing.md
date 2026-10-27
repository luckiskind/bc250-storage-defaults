# Stage 1 shared disk-lookup observer experiment

This opt-in observer variant tests a smaller kernel callback cost. It changes
no production profile, adds no service or persistent BPF pin, and preserves
the original observer and earlier failed overhead evidence. It is measurement
work toward the system-wide accelerator, not an accelerator itself.

## Isolated change

The original device filter separately traverses request, queue and disk to
read major and minor numbers. `bench/qualify_shared_disk.py` derives a private
source tree that reuses the disk pointer within each callback. The derivation
requires exactly one frozen source anchor; missing or repeated anchors refuse.
The qualified original source and binary hashes must still match.

The [installed libbpf CO-RE header](https://github.com/libbpf/libbpf/blob/v1.7.0/src/bpf_core_read.h)
explains that pointer-chain access expands into separate checked kernel reads.
Both versions retain those checked CO-RE reads and their device-number filter.
The variant changes only the duplicated traversal; request identity/generation,
operation coverage, timestamps, quality flags, counters, map/ring capacities,
notification policy and output schema stay unchanged. Loader/header/direct-read
worker sources are unchanged. Compiled binary hashes remain explicit; debug
build-directory metadata can differ even for identical C source.

Static disassembly verifies the expected reduction:

| Callback | Original kernel-read helper sites | Shared lookup |
| --- | ---: | ---: |
| Insertion | 7 | 5 |
| Issue | 9 | 7 |
| Requeue | 7 | 5 |
| Completion | 7 | 5 |

These are static call sites, not measured execution counts or proof of a
runtime saving. The new timing comparison below tests that separate hypothesis.

## Native transport controls

Seven cases reuse the original ABI/build/read/forced-exit checks and the
already qualified cap/consumption controls. Exact known read accounting uses
the worker's recorded window, while whole-capture totals/flags stay visible.
No historical result is recomputed or pooled.

The serial control accounts for 2,048 reads / 8 MiB, with 50 additional
non-read records in its full capture. The concurrent same-location control
accounts for 8,192 reads / 32 MiB. Both keep the disposable file's data pages
nonresident before and after. A deliberate 16-record cap remains incomplete.
Forced observer exit releases the owned programs. An early interrupt drains
all eight reads / 32 KiB at 3.183 ms. The stalled-consumer case explicitly
reports 45,102 ring-lost records plus 74,898 saved records for 120,000 final
events; it correctly remains incomplete. Overflow and interrupt controls are
transport tests, not successful complete captures or performance results.

The [qualification evidence](evidence/stage1-shared-disk.json) records all case
details, source/build hashes, static helper sites and scope. Only new private
fixtures are written or evicted; the original source/fixture and installed
profile are retained. No broader error, partial-completion, requeue or
foreground-dependency qualification follows from these ordinary-read controls.

## Frozen same-fixture comparison

`bench/compare_disk_lookup.py` and `analysis/disk_lookup.py` preserve the prior
three-condition design and strict screening logic in separate files. Seed 252
fixes 24 balanced randomized blocks: all six off/original/shared permutations
occur four times. A warmup block precedes 72 measured trials, for 75 total.
Every condition uses the same new physical NOCOW 64 MiB fixture and the original
worker binary, with 8,192 strided aligned 4 KiB direct reads per trial.

The full order, source/binary/fixture hashes and thresholds are written before
collection. The contract file is fsynced before collection. Progress output,
request captures and result files are deferred until collection ends, avoiding
that source of writeback during later trials. Existing host activity remains
observable context, subject to the frozen exclusions; the system is not assumed
fully idle because the runner is quiet.

The unchanged limits are 3% geometric overhead and a 5% upper exploratory
paired 95% interval, with at least 20 valid blocks. Environmental exclusions
remove an entire three-condition block. Any failed whole-capture quality screen
prevents promotion even if that block also has an environment exclusion.
CPU policy must match within and across block snapshots. This milestone does
not apply the later flush lifecycle findings to relax those screens.

The endpoint is worker barrier-to-join elapsed time. Observer startup/output
serialization are outside that interval; reported process CPU omits some BPF
kernel callback cost. Bootstrap intervals are exploratory and do not establish
independent samples or application effects. Earlier allocations/batches are not
pooled, and an unchanged experiment is not repeated to obtain a pass.

| Comparison, same 18 valid blocks | Geometric elapsed-time difference | Exploratory paired 95% interval |
| --- | ---: | ---: |
| Original versus off | +3.423% | +1.233% to +5.748% |
| Shared lookup versus off | +2.311% | +0.038% to +4.737% |
| Shared lookup versus original | -1.075% | -2.529% to +0.458% |

**Decision: no demonstrated relative benefit; do not promote.** The relative
interval crosses zero. Only 18 of 24 blocks qualify, below the frozen minimum
of 20, and capture failures prevent an overall pass regardless of the numerical
limits. The shared variant's point/interval versus off fit the numerical
limits in this batch; the original's do not. Neither passes the full screen.

Environment exclusions affect blocks 3, 4, 13, 18 and 23 for preceding device
activity. Failed captures are shared in 3, 13 and 23, and original in 9 and 18.
Each failed capture contains one zero-byte operation-2 record with flag 144
(missing insertion plus zero bytes) and one unmatched completion. The flagged
record is outside the dedicated workload window; no read is flagged. Map/ring
loss, zero generations and right censoring remain zero. This pattern is
consistent with the [separate lifecycle investigation](request-lifecycle.md),
but equal counts do not identify the specific unmatched request or erase the
old screen. All 50 instrumented trials account for exactly 8,192 reads / 32 MiB
with no flagged record inside the dedicated worker window. No failure is reclassified.

All 75 trials have no observed cgroup CPU throttling and retain constant CPU
policy within each trial; the runner also checks policy across each measured
block. The [comparison evidence](evidence/stage1-disk-lookup-comparison.json)
retains all timing rows, exclusions, capture diagnostics and the unchanged
decision. Raw captures and detailed snapshots stay private. There is no
unchanged repeat scheduled to obtain a pass.

## Bounds and remaining gate

Native qualification uses a private mount namespace, two CPU equivalents,
2 GiB memory, zero swap, 128 tasks and a five-minute lifetime. Comparison uses
the same memory/CPU/swap/lifetime ceilings as the previous calibration.
The request map remains 8,192 entries, ring 4 MiB and saved-record cap 200,000.
The 72 GiB host space floor remains. New fixtures, retained captures and logs
add lab writes and space; they neither reset nor expand production maintenance
quotas and do not measure NAND writes. Global tracing, unrelated program
inventory, fixture contents and 5000 us power policy must verify after runs.

Stage 1 remains open. The next observer must account explicitly for the
identity-level lifecycle patterns and qualify that handling on new controlled
cases, while further reducing callback cost if necessary. A passing synthetic screen would still leave real
workload endpoints/cache closure, wrapper cost, page-fault/filesystem/decompression
coverage and foreground storage dependencies to qualify. A failed screen
requires a changed implementation or method supported by new evidence.

## Reproduction

```sh
sudo python3 bench/qualify_shared_disk.py run \
  --qualified /absolute/private-lab/original-passing-qualification \
  --output /absolute/private-lab/new-shared-lookup-qualification
sudo python3 bench/compare_disk_lookup.py run \
  --original /absolute/private-lab/original-passing-qualification \
  --shared /absolute/private-lab/new-shared-lookup-qualification \
  --output /absolute/private-lab/new-shared-lookup-comparison
```

Existing directories are refused. Raw traces and detailed snapshots stay private;
reviewed aggregate results retain every trial, exclusion and failed screen.

The [lifecycle-aware v2 implementation](trace-v2.md) now passes its scoped native
identity/proof and negative controls. Its prospective schema keeps raw flags and
unknown completions visible, without changing this earlier result. V2 overhead,
actual reversed kernel callback order and foreground attribution remain open.

A later [v2 calibration](trace-v2-overhead.md) passes its two synthetic overhead
control screens, with every trial and exclusion retained. This does not change
this historical experiment or qualify real application cost/attribution.
