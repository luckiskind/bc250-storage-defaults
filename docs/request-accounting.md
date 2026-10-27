# Stage 1: distinguish issued bytes from reported bytes

Status: the separate accounting revision passes replay of **13 frozen native
captures**, one **explicitly synthetic censored prefix**, and **262 Linux tests**.
No new kernel collection or workload was run. The existing 14 native request
controls and every old source, binary, raw record and verdict remain intact.
This fixes incomplete-result labeling before application use; it establishes
no additional storage speed or native fault-path qualification.

## The issue and correction

The frozen request reader's `request_reported_total_bytes` sums the initial
issued request sizes. That equals the fully reported total in a quality-passed
complete graph, but overstates completed reporting when collection is censored.
The new `analysis/request_bio_accounting.py` first runs that strict frozen reader
and then separates issue snapshots from observed parented completion chunks.
Its output carries `request_accounting_revision: 1`; the raw wire protocol is
unchanged. Consumers of the revised result should use its explicit fields.

| Field | Meaning |
| --- | --- |
| `request_issued_total_bytes` | Initial sizes of observed selected-request issue snapshots, including unselected members in those requests |
| `request_reported_total_bytes` | Bytes in observed completion chunks with an already observed request and member parent |
| `selected_request_issued_member_bytes` | Initial sizes of observed members bound to selected physical bios |
| `selected_request_reported_member_bytes` | Observed parented completion-chunk bytes for those selected members |
| `unresolved_completion_chunk_records/bytes` | Chunks lacking an earlier matching parent snapshot; never silently attributed |

The older `selected_request_member_bytes` field retains its snapshot-size
meaning for compatibility. Complete quality-passed captures require issued and
reported totals to agree, selected totals to agree, no unresolved chunk, and
the selected reported total to equal physical completion reports. Error-status
chunks still report kernel completion bytes; that does not establish a
successful application read. Graph quality remains false on errors.

The revision preserves stable event ordering for equal timestamps. A chunk
that appears before its parent cannot gain ownership retrospectively from a
later member record. Validation rejects malformed identities or byte prefixes;
the revision does not waive the original quality verdict.

## Replay evidence

The [reviewed record](evidence/stage1-request-accounting.json) anchors the parent
native result and every raw-capture hash to the previously published reviewed
evidence. Source and compiled hashes are checked before replay. All 13 original
verdicts are preserved, and every complete valid total stays unchanged.

One additional test takes the original compressed cold trace only through its
first completion chunk. Its counters are reconstructed and its open-context
markers are conservatively synthetic. It is **not an actual native stop**, a
partial-device completion, or another hardware trial.

| Interpretation of that synthetic prefix | Bytes |
| --- | ---: |
| Legacy field labeled reported | 196,608 |
| Revised issued total | 196,608 |
| Revised observed reported total | 12,288 |

Both readers reject the prefix as incomplete. The correction changes byte
labeling, not that verdict. Unit tests additionally cover mixed selected and
unselected members, an orphan preceding its later snapshot, error-status
reporting and source-input immutability. Synthetic graphs do not qualify those
paths natively. A preliminary replay lacked the final raw-review hash anchor;
the retained final replay adds that anchor. One earlier launcher failed before
starting Python because it used a relative path. Neither is a hardware trial.

The final replay runs with a 512 MiB memory limit, 100% CPU quota, no swap,
64-task limit and 60-second lifetime. It reads existing protected evidence and
creates only a fresh private result directory. It starts no BPF observer or
foreground workload. The full Linux suite and syntax checks pass. All seven
installed profile files, original boot configuration, 5000 us setting, quota
history and active/enabled power service and timer remain verified.

## Read-only preparation for combined causality

Actual BTF records `bio_vec` as 16 bytes, `page` as 64 and `folio` as 256. The
bio vector contains a page pointer, length and offset. The installed kernel
uses `compound_info`, and its head-conversion logic can use a mask according to
configuration; an unconditional older pointer-plus-one decoder is unsuitable.
The installed header hashes and selected configuration are retained with the
layout offsets. The upstream
[page/folio conversion implementation](https://raw.githubusercontent.com/torvalds/linux/v7.2/include/linux/page-flags.h)
provides source context; actual host layouts and configuration are authoritative.

The official virtual block-test driver modules are available but remain
unloaded and unconfigured. No error, requeue or partial completion was injected.
A later private virtual target may qualify common block-layer behavior, but
cannot silently qualify physical NVMe driver errors. Production device guards
remain unchanged.

The next combined observer needs saved original iterator/vector identity,
bounded inspection of actual folio-vector overlap, correct multi-page/large
folio geometry, and explicit cross-edges to the request graph. The previous
callback/range proof alone is insufficient. Combined native controls, broad
path coverage, total tracing cost, whole-application critical paths and the
Stage 1 workload suite remain open. Suspend/wake stays excluded as unsupported.
