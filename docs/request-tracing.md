# Request-identity observer: initial qualification

The [recorded five-case matrix](evidence/stage1-request-trace.json) qualifies
ordinary full-request accounting on the actual BC-250 kernel. It does not yet
qualify application attribution, tracing overhead, partial/error/requeue paths,
hardware-only service latency or an accelerator performance improvement.

## What changed

Formatted block events omit the request pointer needed to distinguish concurrent
requests to the same disk location. The observer uses read-only raw tracepoint
arguments, with signatures checked against the running kernel's BTF metadata.
CO-RE reads the current request structure; the key combines its pointer and a
nonzero allocation `start_time_ns`. Kernel pointers and allocation stamps remain
inside a bounded private BPF map. Output uses an anonymous per-observer sequence.

The running kernel's trace header explicitly defines completion as potentially
partial. See the [kernel block trace definitions](https://github.com/torvalds/linux/blob/master/include/trace/events/block.h),
[BTF documentation](https://docs.kernel.org/bpf/btf.html) and
[libbpf attachment API](https://github.com/torvalds/linux/blob/master/tools/lib/bpf/libbpf.h).
The artifact pins its actual local trace-header/BTF hashes; upstream master is
background documentation, not an assumed ABI for this kernel.

Four temporary programs observe insertion, issue, requeue and completion. They
write only their own maps/ring buffer, never request/device state. Insert-to-issue
and issue-to-final-completion intervals use the kernel monotonic clock. These
intervals include kernel/driver and instrumentation effects; they are not pure
SSD hardware latency or a proven foreground critical path.

Repeated insertion/issue, requeue, error, partial completion, missing insertion,
zero-byte operations and invalid ordering are flagged and excluded from the
ordinary full-request timing summary. Zero generation, map-update failure,
orphan events, ring loss and unfinished entries are counted. A successful map
delete owns the final record; identity reuse across completed requests does not
reuse the output sequence. Edge-path handling is conservative and still needs
its own fault/replay qualification.

## Observed matrix

| Case | Known reads | Captured records | Result |
| --- | ---: | ---: | --- |
| No dedicated workload, two seconds | 0 | 0 in the accepted run | No invented requests |
| Serial aligned reads | 2,048 × 4 KiB = 8 MiB | 2,048 | Exact bytes/identities; zero flagged/lost/orphan events |
| Four readers repeatedly accessing the same location | 8,192 × 4 KiB = 32 MiB | 8,192 | Exact bytes and unique identities despite overlapping disk locations |
| Deliberate 16-record cap | 1,024 reads requested | 16 saved; 17 final kernel events | One explicit discarded record and one unfinished entry; capture correctly marked incomplete |
| Forced observer termination | None | No performance result | All four owned program IDs disappear after SIGKILL |

The serial/concurrent fixture has zero resident file bytes before and after the
reads. An initial warm-fixture, unprefaulted-buffer diagnostic observed 511 NVMe
reads for 512 requested reads. It failed the check and was retained. The accepted
control prefaults each aligned destination buffer and verifies targeted fixture
eviction/residency; it does not lower the expected request count. These combined
changes fix the control, but the precise cause of the initial missing read was
not isolated independently. A first-load build also exposed optional unnamed
existing BPF programs; inventory handling now treats names as optional.

The 64 MiB random NOCOW fixture remains byte-identical. Only this new private
regular file is written; reads use aligned `O_DIRECT`. Per-file cache eviction
is limited to that fixture. Global page-cache reset, filesystem formatting,
drive-policy changes and program/device fault injection are not performed.

All owned programs are gone after normal exit and forced termination. No maps
are pinned. Existing global trace configuration and the unrelated program
inventory match their before records. The working seven-file profile still
verifies, with its original boot menu, 5000 us drive policy, no pending
transaction and quota history retained. The Linux suite passes 124 tests.

## Bounds and reproduction

`bench/qualify_request_trace.py` builds from the running kernel's metadata using
the installed clang/gcc/libbpf toolchain. Its wrapper creates a private mount
namespace and bounds the whole process group to two CPU equivalents, 2 GiB RAM,
no swap and five minutes. It requires Btrfs, an unambiguous actual NVMe mapping,
the expected raw callback signatures, operation encoding and actual 5000 us
policy. Existing outputs are refused; failed outputs remain for diagnosis.

```sh
sudo python3 bench/qualify_request_trace.py run \
  --output /absolute/private-lab/new-request-qualification
```

The request map holds at most 8,192 entries, the ring has 4 MiB, and saved records
are capped at 200,000. The loader allows at most 60 seconds; qualification uses
short windows. It buffers records in memory and writes them after detachment,
so trace-file output does not create recursive observed disk traffic. The
loader never installs a service or persistent hook. Only its own live process
is terminated by the forced-exit test.

The [v1 JSON schema](../bench/request-trace-v1.schema.json) exports no kernel
pointers, allocation-generation values, sectors, filenames, PIDs or process
names. Monotonic timestamps are unsigned integer nanoseconds; consumers must
preserve 64-bit integers exactly. An actual serial trace validates with a
standard Draft 2020-12 validator; an unexpected `request_ptr` field is rejected.
Raw captures remain private even though identifying fields are omitted.

`analysis/request_trace.py` independently checks unique IDs, capture lifetime,
byte/timing sums, histograms, quality flags and final-event delivery accounting.
Unit counterexamples reject a reused identity and a missing final record, and
accept an explicitly capped capture only as incomplete. Transport completeness
does not erase orphan/censored boundaries or establish application coverage.

## Next gate

Quantify observer overhead against uninstrumented runs, freeze real workload
endpoints/cache procedures, extend controlled edge-path qualification, and
correlate faults/filesystem/decompression with usable-state and frame markers.
No current request timing is used to claim a system-wide loading gain. The
[Stage 1 workload gate](workloads.md) remains open.
