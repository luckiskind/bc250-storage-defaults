# Stage 1: original-to-physical bio bridge

Status: the separate 22-program diagnostic passes 12 native controls. Four cold
worker cases link 53 original bios to 53 physical-input roots, with 20 split
children and 73 full bio completion reports. Independent byte partitions account
for 6,881,280 reported physical-input bytes without gaps or overlap. It does not yet connect bios to NVMe request generations or join
the earlier folio-wake extension. Stage 1 remains open; no new accelerator
speed result follows from this instrumentation work.

## Preserve the references

The new BPF source includes the unchanged 16-program
[read-lineage reference](read-lineage.md). Six additional programs observe the
compressed callback's own entry, Btrfs physical-input submission, bio splitting
at entry/return, raw bio queue and raw request completion. A checked
loader derivation produces a separate executable with 22 active programs.
The [folio-wake diagnostic](folio-wait-lineage.md) and
[six-program request v2 observer](trace-v2.md) retain their own sources, result
formats, binaries and qualifications.

The runner checks 14 actual BTF signatures, freezes source/generated-loader/BTF
header/compiled hashes before collection, and verifies the old read-lineage
source and binaries. The new `bc250-physical-bio-diagnostic` kind has its own
[schema](../bench/physical-bio-lineage.schema.json) and mandatory graph reader.
It never reinterprets historical raw results.

## Compressed type identity without exposing addresses

An original data bio and its compressed-input bio are different objects.
Selected inode identity alone is insufficient permission to treat an arbitrary
`btrfs_bio` as a `compressed_bio`.

This host returns hidden addresses from `/proc/kallsyms`, including in the root
session. The diagnostic does not change that setting. Instead a BTF-attached
callback entry uses `bpf_get_func_ip` to witness its own target function's
identity. A separate private compressed calibration read runs while selected
tracking is disabled. The loader waits for an explicit parent handshake and
refuses to enable collection unless the temporary identity map is populated.
No symbol address enters arguments, logs, traces, result files or public data.
The identity map is never pinned and disappears with the observer.

At `btrfs_submit_bbio`, a plain original must already exist in the selected
logical-bio map. Otherwise the callback pointer must equal the witnessed
compressed-read callback before the container is decoded. Its `orig_bbio`
must then resolve to the selected original object. Unsupported repair,
alternate callback, missing identity and untracked original paths remain
unknown and fail quality. Issue PID, sector proximity and timing do not supply
ownership proof.

Calibration can warm the selected compressed fixture. The runner therefore
re-establishes and measures the selected target's private cold/warm cache state
after calibration and before releasing the paused worker. It never resets the
global page cache.

## Physical partitions and lifecycle

Each accepted physical-input bio receives an anonymous ID under its original
logical bio. A split requires a tracked live parent, a positive strict-prefix
length, a saved entry context and a successful returned child with the expected
size. The child receives its own ID; its parent loses exactly that prefix.
No original argument is dereferenced at split return. The returned child is
read while its caller still owns it. Pointer reuse, invalid size, missing
context and map insertion failure fail quality.

The raw queue event verifies the actual bio's NVMe disk and read operation.
Splits after this boundary inherit that proven device relationship; splits
before it need their own boundary evidence. At raw request completion, a bounded
walk inspects the actual request's completed bio-chain prefix before the kernel
advances or frees those bios. A selected bio needs live object/device proof,
its full expected remaining size and enough reported completion bytes. Partial
selected-bio updates and an unexamined prefix beyond 64 bios fail quality.
The event records the fully reported slice before deleting its temporary
context. These are block-layer completion reports, not a census of final
`bio_endio` callbacks or a hardware timing measurement. Completed slices must
partition each initial physical bio's
byte range exactly once, without gaps or overlaps. Boundary visits are not
summed as device bytes: a bio may split or visit the boundary again.

The earlier raw bio-completion experiment received no events and failed
quality. Upstream request completion explicitly clears `BIO_TRACE_COMPLETION`
before ending each bio, preventing that raw bio hook from being a complete
observer of this path. Both normal and fast completion paths contain this
behavior. Adding the raw queue hook alone did not close the gap. The new
request-completion prefix hook observes the live members before that clearing;
missing completions were not waived or inferred from worker success.

The source background is upstream Linux's
[Btrfs mapping/split path](https://raw.githubusercontent.com/torvalds/linux/v7.2/fs/btrfs/bio.c),
[block submission path](https://raw.githubusercontent.com/torvalds/linux/v7.2/block/blk-core.c)
and [bio splitting/completion](https://raw.githubusercontent.com/torvalds/linux/v7.2/block/bio.c).
The [request completion implementation](https://raw.githubusercontent.com/torvalds/linux/v7.2/block/blk-mq.c)
defines the completion-prefix and trace-flag behavior above.
Actual attachment and native controls qualify only this installed kernel.
Available BTF symbols alone are not evidence of event coverage.

## Bounds and diagnostic counters

The parent has a 2 GiB memory limit, CPU quota of 200%, no swap, 128-task limit,
300-second lifetime and a private mount namespace. Two disposable 8 MiB plain
and compressed fixtures use the unchanged reference worker's 2 MiB buffered
or mapped read and content check. Calibration reads one private 8 MiB file per
capture. The host free-space floor is 72 GiB. Each of seven context maps holds
at most 4096 entries; the ring is 4 MiB, captures last three seconds, and at
most 50,000 records are saved. All links detach before saved traces are emitted.

The 16 physical counters are: callback-entry observations (0), identity
inconsistency (1), unknown selected physical root (2), map insertion failure
(3), reserved (4), invalid/error split (5), split-context inconsistency (6),
reserved (7), wrong device/operation/range (8), completion without device proof
(9), status error (10), context deletion failure (11), all observed NVMe read
request-completion callbacks (12), all observed raw bio queue callbacks (13),
partial/inconsistent selected-bio completion (14), and truncated/inconsistent
request completion prefix (15). Counters 12–13 include unrelated I/O and establish
no foreground ownership. Only 0, 12 and 13 may be nonzero in a clean positive
control; losses, remaining contexts, unknown roots and bad graph edges fail.

## Observed native controls

The [reviewed evidence](evidence/stage1-physical-bio-lineage.json) retains five
attempts. Attempt 1 failed compilation before attachment; attempt 2 calibrated
identity but rejected a fragmented readiness line before releasing the worker.
Attempts 3 and 4 each completed a correct plain read but rejected absent raw
bio-completion coverage. Only attempt 5 uses the final source and passes the
full matrix; no historical measurements are pooled into its result.

| Case | Original bios | Physical roots | Split children | Full completion reports | Reported bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| plain-read-cold | 1 | 1 | 7 | 8 | 2097152 |
| plain-read-warm | 0 | 0 | 0 | 0 | 0 |
| plain-mmap-cold | 4 | 4 | 13 | 17 | 4194304 |
| plain-mmap-warm | 0 | 0 | 0 | 0 | 0 |
| compressed-read-cold | 16 | 16 | 0 | 16 | 196608 |
| compressed-read-warm | 0 | 0 | 0 | 0 | 0 |
| compressed-mmap-cold | 32 | 32 | 0 | 32 | 393216 |
| compressed-mmap-warm | 0 | 0 | 0 | 0 | 0 |

All eight positive streams close every context with no transport loss, unknown
root or error counter. The four warm cases issue no selected data bio. Native
block-layer splitting after the device boundary is positively exercised; a
pre-device/Btrfs mapping split is not. The 2 MiB plain buffered read becomes
eight 256 KiB completion slices. These controlled generated-data sizes do not
establish compression savings or speedups for real applications.

The same-inode/different-open-description negative emits no selected events.
The four-record cap is explicitly incomplete. Forced loader exit removes all
22 programs. Disabling callback proof preserves valid worker bytes but leaves
16 compressed originals uncovered and correctly fails quality.

Independent review re-parses all 11 retained raw streams and reconstructs
terminal byte partitions separately from the reader's mutable split algorithm.
Source, generated loader, compiled binaries, BTF header, full fixture hashes
and frozen reference hashes all match after collection. All seven installed
profile files, boot configuration, 5000 us policy, existing quota charges and
active/enabled power service and timer remain verified. The full Linux suite
passes **247 tests**, plus syntax checks.

## Remaining qualification

Full bio-vector membership, request chains and merges, request generation
reuse, partial/error/requeue paths and native cross-chunk/mirror behavior still
need independent controls. The earlier folio wake proof is a separate result;
combining the two requires a new protocol and qualification. Instrumentation
cost for this 22-program observer is unmeasured. Neither the request-v2 cost
screen nor selected application timings transfer to it. Whole application
critical paths and the Stage 1 workload suite remain open. Suspend/wake tests
are excluded because the user confirms the BC-250 has no functional suspend
wake support.
