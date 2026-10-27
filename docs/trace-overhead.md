# Stage 1 observer overhead: failed serial-read screen

The unchanged request observer does **not** pass its prespecified exploratory
overhead screen on this BC-250. Keep it opt-in; do not use it to certify small
application gains. Stage 1 and the complete accelerator goal remain open.

## Results

Two separately frozen batches contain 86 trials, including six warmups. Both
use the previously qualified observer, BPF object and direct-read worker
without rebuilding or changing their bytes. Each workload reads 32 MiB in
aligned 4 KiB operations. The serial control makes 8,192 strided reads; the
concurrent control uses four readers, each repeating 2,048 same-location reads.

| Batch and control | Valid pairs / planned | Geometric elapsed-time overhead | Exploratory paired bootstrap 95% interval | Screen |
| --- | ---: | ---: | ---: | --- |
| Pilot, serial | 7 / 8 | +2.407% | -2.651% to +7.263% | Fail: upper interval |
| Pilot, concurrent | 7 / 8 | +0.945% | -1.078% to +3.131% | Pass for this control only |
| Fixed precision extension, serial | 20 / 24 | +4.460% | +2.191% to +6.706% | Fail: point, upper interval and strict capture screen |

These are observer costs, not accelerator improvements. The two serial batches
use fresh independently allocated copies of the same fixture bytes; they are
reported separately and are not pooled or treated as an implementation change.
The intervals resample pairs, using 5,000 draws and a fixed seed. They do not
establish independent observations, a causal bottleneck or application overhead.

Reviewed evidence includes every lightweight timing row, order, exclusions,
source/binary hashes and failed-screen diagnostics:

- [Pilot evidence](evidence/stage1-trace-overhead-pilot.json)
- [Fixed extension evidence](evidence/stage1-trace-overhead-refined.json)

Raw request records and detailed machine snapshots remain private. Public
evidence contains no request pointers, allocation stamps, sectors, filenames,
PIDs, host identifiers or arbitrary local paths.

## Frozen method and decision rules

`bench/measure_trace_overhead.py` writes its contract before collection. It
randomizes balanced observer-on/off pair orientations with seed 250. Both
conditions have a common 250 ms post-setup idle interval and approximately
two-second slots. The endpoint is the worker's own barrier-to-join interval;
observer startup and final trace serialization are outside it. Startup is
reported separately. The original screen requires at least six valid pairs,
geometric overhead at most 3%, and an upper interval bound at most 5%.

`bench/refine_trace_overhead.py` freezes one serial-only extension of 24 pairs,
requiring at least 20 valid pairs, with unchanged thresholds, observer and
workload. Its source hash is saved in the contract. There was no unchanged
repeat-until-pass sequence or retrospective threshold adjustment.

Prespecified environment exclusions cover pre-workload aggregate CPU busy time
over 10%, more than 128 KiB of device traffic in the preceding idle interval,
less than 2 GiB sampled available memory, more than 128 KiB of additional
device traffic during the workload, and a CPU policy change within a trial.
An exclusion removes the whole pair from the elapsed-time estimate. Rows are
retained. A failed capture screen cannot be discarded to obtain a passing
overall verdict, even when its pair also has environmental interference.

Pilot exclusions are serial pair 6 and concurrent pair 5, both for preceding
device activity. Extension exclusions are pairs 6 and 14 for preceding device
activity, and pair 21 for additional device I/O. Pair numbers are zero-based.
CPU policies were additionally verified constant across all recorded snapshots
in each batch; no measured trial had cgroup CPU throttling.

The entire run is limited to two CPU equivalents, 2 GiB memory, no swap and
five minutes in a private mount namespace. It creates only a new 64 MiB regular
NOCOW fixture, checks unshared/unencoded extents and content hashes, and uses
per-file eviction/residency checks. Fixture residency is zero before/after each
read workload. It never drops the global page cache. Trace output stays in RAM
until collection ends to avoid earlier trace-file writeback affecting later
pairs. Process CPU accounting does not include all kernel BPF callback cost.

## Capture-screen failures

The extension retains strict failures for pairs 14, 21 and 23. Each captured
exactly the expected 33,554,432 read bytes and reported zero ring loss,
map-update failures, zero generations and right-censored requests. They also
contained respectively one, one and three zero-byte records lacking an insert
event (flag 144), with matching orphan-completion counters. The flagged issue
was inside the workload window only for pair 21; the others were outside it.

The screen examines the whole capture window, including background/boundary
activity. These flags do not prove lost read data. Flush/background lifecycle
semantics are a hypothesis; their cause is not isolated. The original strict
criteria are retained, and zero-data/boundary behavior needs qualification
before broader application tracing. No partial/requeue/error-path coverage is
claimed from these runs.

## Reproduction and preservation

Run on the qualified host against a retained passing request-identity artifact:

```sh
sudo python3 bench/measure_trace_overhead.py run \
  --qualified /absolute/private-lab/passing-request-qualification \
  --output /absolute/private-lab/new-overhead-pilot
sudo python3 bench/refine_trace_overhead.py run \
  --qualified /absolute/private-lab/passing-request-qualification \
  --output /absolute/private-lab/new-overhead-extension
```

The tools refuse existing outputs and changed qualified source/binary hashes.
Do not rerun solely to seek a favorable result. Both completed artifacts remain
available privately. All owned BPF programs are gone, unrelated program
inventories and global tracing match, fixture hashes match and NVMe latency
tolerance remains 5000 us. A post-run health check verifies all seven installed
profile files, the original boot configuration and retained daily charges.
The isolated Linux suite passes 127 tests. These tools install no service.

## Next experiment

Preserve this baseline and build a distinct observer variant that batches
ring-buffer consumption. The [kernel ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html)
describes notification controls and warns that manual notification requires
care. Test suppressing per-record notifications with `BPF_RB_NO_WAKEUP` and
explicit bounded periodic consumption/final drain. Kernel event timestamps and
request identity must stay unchanged; overflow/cap/exit behavior must be
requalified before comparing overhead. Excess wakeups are a hypothesis, not a
profiled cause.

Compare baseline and variant in a newly frozen balanced experiment using the
same physical fixture within that experiment. Do not loosen the old screen or
compare the independently allocated historical batches as a variant effect.
Then qualify application endpoints, cache state, edge paths and dependency
attribution before the roadmap's B0/B1/B2 performance comparisons.

## Follow-up completed

The proposed separate [batched-consumption experiment](batched-tracing.md) is now measured. It shows no demonstrated reduction and does not pass its strict screen. The original results above remain unchanged. Continue with lifecycle qualification, probe-cost evidence and concrete workload definitions instead of repeating notification tuning without new evidence.
