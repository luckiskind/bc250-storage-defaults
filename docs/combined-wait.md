# Stage 1: combined request, vector and folio wait evidence

Status: the separate **29-program** diagnostic passes **16 native controls**.
Nine positive cases account for 102 request generations, 143 selected bio
members, three multi-bio requests, four changed-generation request-address
reuses and 23,658,496 selected reported input bytes. All **24 observed blocked
segments** have both an actual folio-vector edge and a reported request
dependency. These are selected-worker functional controls, not a whole-app
critical path or an acceleration result. Stage 1 and the ten-stage goal remain
open. The full Linux suite passes 274 tests.

## Preserve the references

The new BPF source includes the frozen request/bio observer. A checked loader
derivation disables five replaced logical/sleep programs and composes a checked
folio extension with the request programs. The older physical completion hook
remains disabled. There are 29 actual owned program IDs, 13 pending context
maps and a separate bounded request history registry. Old sources, binaries,
raw formats, results and failed cost verdicts remain unchanged.

The runner checks four saved qualification references and 20 actual BTF
function/callback signatures. Before collection it freezes source, generated
loader/folio header, BTF header and compiled binary hashes. The new
`bc250-combined-wait-diagnostic` kind has its own [schema](../bench/combined-wait.schema.json)
and [reader](../analysis/combined_wait.py). After combined delivery accounting,
that reader projects the unchanged request stages into the accounting reader
and the remapped wake/scheduler stages into the frozen folio reader. Neither
projection can waive failures from the other.

## Actual vectors, saved iterator

At original bio submission, private maps bookmark the actual vector-array
pointer, original iterator index/consumed bytes and count. At data-end entry,
that bookmark transfers to the current callback context and is retired at
return. Return hooks never dereference a possibly freed original argument.

Before recording a matched queued-folio wake, the combined observer inspects
the active original bio's vector array, starting at the saved iterator and
trimming its consumed first-vector prefix. The current array must match;
count, index, lengths and reads have explicit bounds, with at most 256 vectors.
Compressed readahead can append vectors, so their current byte sum is not
mistaken for the original submitted size.

With a verified VMEMMAP, 64-byte page metadata and 4 KiB pages, a shared pure-C
helper intersects actual vector page spans with the queued folio span. It
supports multi-page vectors, nonzero offsets, preceding/tail-page geometry and
large or partial folios in synthetic calculations. It checks overflow and
requires the vector's accumulated file coordinate to equal the folio's file
coordinate. The overlap is clipped to the original submitted range. Native
qualification remains narrower: all observed queued folios were single pages;
three actual proof edges involved multi-page vectors. Large/partial folios and
nonzero initial iterators require separate native controls.

Actual BTF/configuration and installed kernel-source guards verify the layout
and compound-tail low bit. The code does not assume compound metadata always
encodes a head pointer plus one. Head shape, page count, index, selected mapping
and vector-array identity are rechecked. This is not a universal atomic
topology snapshot. Unsupported, changed, unreadable or unmatched states are
explicit failures, not inferred ownership.

The new stage 30 edge carries the matched wake's anonymous ID, original bio ID,
overlap offset/length, folio size/offset and geometry flags. No page, bio, task
or request addresses are exported. The old callback/range proof alone cannot
satisfy the new reader.

## Request reports before the callback

The reader follows actual physical root/split ancestry from that original bio
to actual issue-time request member IDs. Every selected physical slice needs
full ordered completion chunks, a corresponding physical terminal report and
a report time preceding its logical callback. The original callback, vector
proof, queued folio and scheduler wake must agree. The independent review
flattens those ancestry and byte-report relationships separately.

This establishes an object dependency. A compressed original can depend on
all its physical input before decompression and wake; the proof does not claim
each input byte was the minimal hardware cause of a stall. Scheduler delay,
wake delivery, decompression wall spans and blocked intervals retain their
distinct meanings. Request queue wait, CPU-only decompression cost and a
whole-application critical path remain unqualified.

## Controls and retained attempts

| Control | Result |
| --- | --- |
| Plain/encoded buffered/mapped, cold/warm | Eight content-checked cases pass; four cold cases resolve five blocked segments; warm cases have no data I/O |
| Serialized cold reuse | Eight separately verified zero-resident passes; 19 request-backed blocked segments |
| Same inode, different open description | No selected events; positive identity rejections |
| Four-record cap | Explicitly incomplete; quality fails |
| Forced observer exit | All 29 owned programs disappear |
| Callback proof disabled | Valid bytes, missing original-to-physical ownership; quality fails |
| Issue proof disabled | Valid bytes, missing request ownership; quality fails |
| Folio proof disabled | Valid bytes, unresolved blocked wake; quality fails |
| Vector proof disabled | Older range/scheduler proof remains, actual vector proof is missing; quality fails |

The first attempt hit verifier state complexity inside the vector loop. The
second used an independently verified global geometry function but lacked
the explicit null guards required for its pointer parameters. The third
passes all 16 controls. Export verification then found Windows line endings
in the runner. A fourth, fresh qualification uses canonical LF source and
passes the same 16 controls with 24 blocked segments; only this final capture
contributes the totals above. Both failures and the passing precursor remain
recorded, without pooling. The geometry helper passes four native tests, including
600 deterministic cases against an independent unbounded-integer interval
oracle. This does not qualify those synthetic shapes as native I/O behavior.

Each capture has a 4 MiB ring, three-second duration and 50,000-record cap.
The parent has memory, CPU, process, runtime, mount and free-space bounds.
Only disposable private fixtures receive cache eviction; there is no global
cache reset. Owned program cleanup, unrelated tracing inventory, fixture
content and the working installation verify. No persistent observer is
installed. Suspend wake is unsupported and was not attempted.

The [public evidence](evidence/stage1-combined-wait.json) contains only minimal
non-identifying totals and scope limits. Detailed captures, hashes, layouts,
installation and quota records remain local. Native mixed ownership,
partial/error/requeue paths, broader concurrent wake interleavings, large or
partial folios, total 29-program observer cost and whole-workload input/cache
closure remain open. The next gate is a frozen cost experiment before using
this observer to justify system-wide policy changes.
