# Stage 1 native request/flush lifecycle diagnostic

The new diagnostic reproduces two distinct flush-related callback patterns on
the actual BC-250 kernel. It explains a mechanism that can produce zero-byte
records and completions without an issue callback. It does not identify the
cause of each historical unmatched completion, change old failed overhead
verdicts, qualify all flush/error paths, or establish foreground attribution.

## Why another observer was needed

The [original timing observer](request-tracing.md) sees four block callbacks.
Some earlier windows contain a zero-byte operation-2 record without insertion
and an unmatched completion count. Equal counts do not prove that the same
requests caused both. Its [batching experiment](batched-tracing.md) therefore
keeps the failed capture screens and does not promote those timings.

The upstream [Linux flush implementation](https://github.com/torvalds/linux/blob/v7.2/block/blk-flush.c)
provides a hypothesis: software sequencing and an internal device flush can
have different request identities and callback paths. The
[multiqueue implementation](https://github.com/torvalds/linux/blob/v7.2/block/blk-mq.c)
also contains completion tracing outside an ordinary data-request path. These
sources are background evidence; they are not a claim that every implementation
detail in the modified running kernel matches upstream v7.2.

## What the native probes observe

`bench/qualify_request_lifecycle.py` builds a separate six-program diagnostic:
four raw block callbacks plus entry/return probes on `blk_insert_flush`.
The running kernel's BTF verifies the raw callback signatures and the flush
function's request-pointer argument and Boolean return. The build pins BTF,
actual local trace/request-header hashes, sources and compiled objects. Function
entry/return attachment uses the installed libbpf API, documented in its
[v1.7.0 header](https://github.com/libbpf/libbpf/blob/v1.7.0/src/libbpf.h).

Within a bounded private map, request address plus nonzero allocation timestamp
selects an anonymous identity. Each callback carries an ordinal and monotonic
timestamp. It records operation, byte counts, return/error status, request/command
flags, bio presence and whether the actual request pointer equals its hardware
queue's internal flush request. No pointer, allocation timestamp, sector, PID,
filename or process name is exported. A positive internal-request comparison
is evidence; a negative comparison alone does not establish a software sequence.

The final run has three predetermined three-second windows:

| Window | Callback records | Observed identity groups |
| --- | ---: | --- |
| 256 aligned direct reads | 768 | 256 insertion/issue/completion groups; exactly 1 MiB completed |
| Eight private write-and-fdatasync updates, first sequence | 422 | 138 groups, including 8 internal device flushes and 8 zero-payload consumed software sequences |
| Eight private write-and-fdatasync updates, second sequence | 200 | 64 groups, including the same two sets of 8 |

Every direct-read group has insertion, issue and completion callbacks. Each
internal device flush has a positive pointer relationship, operation 2, zero
bytes, no bio, and issue/completion callbacks without insertion. Each software
sequence has entry, a consumed=true return, and later successful completion:
operation 1, zero bytes, a bio, and no ordinary device issue callback. This
identity-level evidence distinguishes the software completions from internal
operation-2 requests rather than inferring that distinction from count equality.

The remaining writes include ordinary data requests and requests whose flush
sequencer returns false before normal insertion/issue/completion. Background
write counts differ between windows and remain visible. Their presence is not
assigned to the test merely because it occurred nearby. These are full capture
patterns, not an ownership or critical-path attribution result.

All final captures have exact callback transport accounting, no ring/map loss,
no zero-generation/drop/malformed records, no completion error, no unexplained
completion pattern under the recorded parser, and no remaining owned program.
Both the read control and whole captures are retained privately. Reviewed
[aggregate evidence](evidence/stage1-request-lifecycle.json) includes the classes.

## Interpretation controls and limits

`analysis/request_lifecycle.py` has a distinct format from timing reports.
It rejects unexpected fields, hidden loss, reused/gapped ordinals, invalid
clocks and out-of-lifetime callbacks. Explicit loss remains incomplete and
prevents either known flush-pattern qualification. A zero-payload read,
standalone completion, negative internal relationship, nonconsumed return or
completion error cannot become an explained flush. Tail callbacks are bounded
by actual detachment, separately from the disable marker. Ten counterexample
tests exercise these conditions.

An earlier build stopped before attachment because a generic map name collided
with a type in the actual kernel BTF. The next run passed transport and showed
the two lifecycle patterns. The final source repeats the controls with an
explicit detach timestamp for conservative tail accounting. Failed/build and
earlier captures remain intact.

The fixture is one new 8 MiB NOCOW regular file. Each synchronization case
updates eight 4 KiB ranges and calls fdatasync only on that file. No raw-device
flush ioctl, global sync/cache reset, formatting, fault injection, profile
change, service installation or persistent BPF pin is used. Only the new file
receives cache eviction; direct-read residency verifies zero before and after.
The controller runs in a private mount namespace and a bounded parent job:
two CPU equivalents, 2 GiB memory, zero swap, 128 tasks and 180
seconds. Limits are 8,192 identities, a 4 MiB ring, 50,000 saved callbacks and
15 seconds per loader invocation. The 72 GiB host space floor remains.
Lab writes are additional to the unchanged production quota; NAND writes are
not measured. Global tracing and unrelated program inventory verify unchanged.

Ring-overflow/signal edges of this new loader, injected errors, partial
completions, requeues, other devices/kernels, broader flush policies, capture
boundaries with in-flight requests and instrument cost remain unqualified.
No new quality-rule change or performance comparison is made in this milestone.

## Next optimization experiment

Static disassembly of the original qualified BPF object finds 7, 9 and 7
`probe_read_kernel` helper call sites in insertion, issue and completion
programs respectively; requeue has 7. These are compiled call sites, not
measured runtime invocation counts or proof of their time cost. The original
source repeats the request-to-queue-to-disk traversal for major and minor.
A separate variant can reuse that disk pointer within each callback and
reduce duplicate helper reads while preserving the existing request identity,
operation coverage, timestamps, quality flags and output semantics. It still
requires native transport qualification and a new frozen overhead comparison.
Typed BTF callbacks are another candidate if the simpler change is insufficient.

Stage 1 remains open. The diagnostic supplies evidence for future lifecycle
handling; it does not turn the original overhead failure into a success or
establish a storage-accelerator gain.

## Reproduction

```sh
sudo python3 bench/qualify_request_lifecycle.py run \
  --output /absolute/private-lab/new-lifecycle-diagnostic
python3 analysis/request_lifecycle.py \
  /absolute/private-lab/new-lifecycle-diagnostic/fsync-sequence-1-raw-private.json
```

The first command qualifies transport. The independent second step describes
observed patterns; private root-owned captures require appropriately scoped
read access. Existing output directories are refused and never overwritten.
