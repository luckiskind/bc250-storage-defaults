# Stage 1: cost of the full combined observer

The fixed 200-trial experiment **does not pass** its four-condition cost screen. All 100 instrumented captures are retained and independently replayed. The complete Linux suite passes 283 tests.

| Condition | Valid pairs / 24 | Overhead | Exploratory 95% interval | Screen |
| --- | ---: | ---: | ---: | --- |
| plain-read | 24 | +0.257% | -0.671% to +1.165% | Pass |
| plain-mmap | 23 | +1.892% | -2.603% to +6.445% | Fail |
| encoded-read | 22 | +3.682% | +1.961% to +6.618% | Fail |
| encoded-mmap | 23 | +7.478% | +4.171% to +12.588% | Fail |

Each condition retains its environmental exclusions, measured capture failures and warm-up failures in the [minimal public evidence](evidence/stage1-combined-wait-cost.json). No excluded failure is waived. This result supplies no accelerator speedup or default promotion.

All conditions meet the sample minimum, with 24, 23, 22 and 23 valid pairs.
Four complete pairs have environmental exclusions; there are no measured or
warm-up capture failures. Plain mapped reads fail the upper uncertainty limit
despite their point estimate being below 3%. Both encoded conditions exceed
the point and upper limits. The unchanged full observer stays opt-in and is
not qualified for general application use. The next experiment should reduce
optional diagnostic work while retaining the actual causal proofs; a new
version must earn its own functional and cost qualifications.

This experiment compares the unchanged
[29-program request/vector/folio observer](combined-wait.md) with no owned
observer at four selected-worker endpoints. It measures the read/fault and
content-hash interval, including synchronous probe work and delay that affects
the worker. It does not measure general application overhead, absolute wrapper
cost or an accelerator gain. Stage 1 and the ten-stage goal remain open.

## Fixed comparison

The hypothesis and complete 200-trial order are frozen and fsynced before any
timing collection. Each plain/encoded x buffered/mapped condition has two
warm-up trials and 24 off/combined pairs. Twelve pairs start in each order,
shuffled with seed 255. Each arm reads the same 2 MiB prefix and verifies the
same FNV hash using the exact qualified worker binary. There is no extension,
adaptive stopping, historical pooling or unchanged repeat to seek a pass.

The observer and worker are copied byte for byte from the qualified native
reference; neither is recompiled. Current source, saved native results,
compiled binaries and actual kernel BTF must match that reference. New plain
and encoded 8 MiB files are independent writes with equal contents and checked
encoding/no-sharing, then retained for both arms. Only these new selected
fixture pages are evicted. Metadata, other process caches and SSD-internal
caches are not claimed cold.

Both arms perform the same private compressed-file calibration read. The on
arm uses it to seed callback identity while selection is disabled. The off arm
does the matching read without an observer. The target is then evicted and
verified zero-resident, followed by the same quarter-second quiet interval.
Setup/calibration/attachment are recorded separately and excluded from the
timed endpoint. Both arms retain the inherited actual descriptor until their
three-second observation/control slot has ended; the on arm must detach first.
Baseline inventory must match the original inventory.

## Quality and environmental rules

Every on trial retains its full capture and runs the strict combined reader.
It needs transport quality, cold demand/original/request coverage, actual
request-backed blocked segments, exact buffered byte accounting where
applicable, content correctness and capture coverage of the worker interval.
Missing proof or lost events cannot count as a faster result. All warm-up and
measured failures remain disqualifying even when a pair also has an
environmental exclusion. Setup, lifecycle or content failure stops collection
and retains the partial schedule; the runner does not retry it.

The same environmental bounds apply in both arms: pre-work CPU activity at
most 10%, available memory at least 2 GiB, quiet-interval device traffic at
most 128 KiB, timed global writes at most 128 KiB and timed global reads at
most the whole 8 MiB fixture plus 128 KiB. CPU policy changes, including changes
within a pair, and parent cgroup throttling exclude the whole pair. Snapshots
also retain CPU, memory/IO pressure, frequency and temperature observations.

The global device bounds do not identify all unrelated I/O. In particular,
background traffic below the bounds can remain. The analysis does not subtract
selected request bytes in one arm and apply a different rule in the other.
Pair resampling is exploratory; independence and general application behavior
are unproven. These limits remain part of the scope of any passing screen.

Each condition requires at least 20 valid pairs, no capture failure, a
geometric mean on/off overhead at most 3% and an upper exploratory 95% paired
percentile interval at most 5%. Resampling uses 5,000 draws and seed 255. Every
condition must pass for the four-condition screen to pass. Per-condition
results and exclusions remain visible even if the combined verdict fails.

## Resource and integrity bounds

The parent has 2 GiB memory, no swap, two CPUs' worth of quota, 128 tasks, a
private mount namespace, the existing free-space floor and a 1,200-second
runtime limit. This finite budget covers the 200 full three-second slots and
setup. Each on capture retains the 4 MiB ring and 50,000-record cap. Aggregate
retained raw/log data is capped at 128 MiB. Trace output is deferred until
collection ends; live progress contains only counts in temporary RAM-backed
storage. It does not write trial results to the measured drive during timing.

At the end, fixture contents, reference contents, source/binary hashes,
unrelated program inventory, trace configuration and drive policy must verify.
The installed defaults are not changed and no persistent observer is enabled.
Detailed environment, hashes, captures and installation checks remain local;
only minimal non-identifying results are public.

The paired analysis and its tests preserve fixed order, insufficient sample
counts, failed warm-ups, quality failures alongside exclusions and true
regressions. Earlier cost screens and their verdicts are unchanged. A failure
here requires a separately versioned reduction in diagnostic cost or a
different explicitly scoped measurement design before application use.
