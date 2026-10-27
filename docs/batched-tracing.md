# Stage 1 batched request observer experiment

Status: opt-in development experiment; no application tracing or accelerator
gain qualified. The original [failed overhead calibration](trace-overhead.md)
remains unchanged. This experiment evaluates a distinct observer variant.

## Change and provenance

`bench/qualify_batched_trace.py` derives a separate source tree from the frozen
original qualification. It refuses changed baseline source/binary hashes. Only
ring-buffer delivery changes: the BPF output uses `BPF_RB_NO_WAKEUP`, and the
loader explicitly consumes records after each 50 ms poll, with a checked final
drain after detaching. Identity, timestamps, filters, counters, record schema,
map capacity and ring size remain unchanged. Baseline source files are retained
byte for byte. The generated source and compiled binaries have separate hashes.

The [kernel ring-buffer documentation](https://docs.kernel.org/bpf/ringbuf.html)
describes manual notification controls and the care needed when using them.
The [libbpf ring-buffer implementation](https://github.com/libbpf/libbpf/blob/v1.7.0/src/ringbuf.c)
is the relevant installed library version. Reduced wakeup overhead is a
hypothesis; these controls do not remove kernel callback/map costs.

No service, persistent BPF pin, boot-menu change, drive-policy change or global
cache reset is introduced. Tests use a new private 64 MiB NOCOW regular file,
aligned direct reads, scoped cache/residency checks, a private mount namespace,
two CPU equivalents, 2 GiB memory, no swap and a five-minute limit. Stop/resume
signals in the overflow test affect only the observer process created by that
test, never the BC-250 or another application.

## Transport qualification

The retained final qualification has seven cases:

| Case | Observed behavior |
| --- | --- |
| Idle | No records in the final run |
| Serial reads | Exactly 2,048 requests and 8 MiB, no flags/loss, zero fixture residency |
| Concurrent same-location reads | Exactly 8,192 requests and 32 MiB, no flags/loss, zero fixture residency |
| Deliberate 16-record cap | Explicitly incomplete; discarded records remain counted |
| Forced observer exit | All four owned BPF programs disappear after SIGKILL |
| Early interrupt | Eight reads / 32 KiB drain exactly on SIGINT at 3.149 ms, before the first 50 ms timeout; trace remains marked interrupted |
| Stopped consumer | 120,000 dedicated reads; ring overflow explicitly reports 45,108 lost records; 74,898 saved plus lost equals 120,006 final events, including background traffic |

The last case intentionally has incomplete transport; it verifies visible loss
and self-consistent accounting, not successful capture of all requests. All
owned programs disappear and the fixture remains unchanged. Partial/requeue/
device-error paths and application dependency attribution remain unqualified.

Earlier development artifacts are retained. The first build passed the original
five transport cases before the two consumption-edge tests existed. The next
attempt failed because the tiny cap could complete during a synchronous
pre-workload program-inventory query. The cap harness now starts dedicated reads
immediately after readiness, checks that saved data includes reads, and verifies
program cleanup after exit. It keeps the cap and incomplete verdict unchanged.

The third attempt failed a new exact whole-capture read check: serial capture
contained 2,048 expected 4 KiB reads plus two 16 KiB background reads. A post hoc
diagnostic found exactly the expected reads inside the worker's start/finish
window. That diagnostic does not turn the failed attempt into a pass. The final
harness freezes timed-window accounting and reports whole-capture accounting
and flags separately. In its new run, both independently pass for the two known
read controls. This does not relax the original overhead screen, whose strict
whole-capture flags remain disqualifying in the comparison below.

[Reviewed qualification evidence](evidence/stage1-batched-trace.json) includes
both baseline and derived source hashes, seven case records and explicit scope.
Raw request data and detailed snapshots stay private.

## Fixed same-fixture comparison

`bench/compare_trace_variants.py` freezes 24 blocks containing observer off,
original observer and batched observer. All six order permutations occur four
times, shuffled with seed 251. One warmup block precedes the 72 measured trials,
for 75 trials total. Every condition uses the same physical NOCOW fixture and
the original direct-read worker binary: 8,192 strided 4 KiB reads per trial.

The contract and source/binary/fixture hashes are written before collection.
The original 3% point / 5% upper-interval limits remain; at least 20 valid blocks
are required. Environmental exclusions remove an entire three-condition block.
Strict failed capture screens are retained and prevent an overall screen pass.
Policy is checked within each trial and across each block. The analysis also
compares batched directly with original using the same valid blocks.

The endpoint remains worker barrier-to-join elapsed time, excluding observer
startup and output serialization. Process CPU is reported separately and does
not include every kernel BPF callback cost. Trace files are written only after
collection ends. Bootstrap intervals are exploratory, not proof of independent
samples or application effects. Historical batches are not pooled.

| Comparison, same 18 valid blocks | Geometric elapsed-time difference | Exploratory paired 95% interval |
| --- | ---: | ---: |
| Original versus off | +0.976% | -1.187% to +3.153% |
| Batched versus off | +1.496% | -1.464% to +4.645% |
| Batched versus original | +0.515% | -1.428% to +2.604% |

**Decision: no demonstrated batching benefit; do not promote.** Only 18 of 24
blocks meet all checks, below the frozen minimum of 20. Whole-block environment
exclusions are 3 and 6 (preceding device activity) and 8 (preceding/additional
device activity). Strict capture failures are original in blocks 6, 9, 13 and
18, and batched in block 8. Each contains zero-byte/missing-insert flag 144;
all flagged issues are outside the dedicated workload window, and ring loss,
map-update failures, zero generations and right censoring are zero. Block 13
also captures 32 KiB of extra reads. These are retained boundary/background
diagnostics, not proof of lost dedicated read bytes. Old criteria are unchanged.

CPU policy is constant across every recorded snapshot and no trial has cgroup
CPU throttling. Both point/interval pairs fall within the numerical limits in
this batch, but the minimum-block and capture rules still fail. Earlier batches
have different allocation/run conditions and are not pooled. No repeat of this
unchanged experiment is scheduled to obtain a pass. All 75 timing rows and the
failed-screen details are in the [comparison evidence](evidence/stage1-trace-variants.json).
The post-run profile health check passes and the Linux suite passes 130 tests.

Next, qualify the zero-byte/flush lifecycle against the actual kernel before
changing any future quality rule. Investigate per-program cost and compiled
helper calls before selecting another observer optimization. Freeze concrete
application endpoints and cache procedures independently; notification tuning
alone has supplied no supported path to system-wide acceleration here.

## Reproduction

```sh
sudo python3 bench/qualify_batched_trace.py run \
  --qualified /absolute/private-lab/original-passing-qualification \
  --output /absolute/private-lab/new-batched-qualification
sudo python3 bench/compare_trace_variants.py run \
  --original /absolute/private-lab/original-passing-qualification \
  --batched /absolute/private-lab/new-batched-qualification \
  --output /absolute/private-lab/new-variant-comparison
```

Existing outputs are refused. Preserve negative results. A passing transport
test does not establish low overhead; a synthetic overhead screen does not
establish application critical-path attribution or an accelerator improvement.
