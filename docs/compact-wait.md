# Stage 1: compact causal diagnostic

The separate compact mode passes **16 native controls with 28 attached
programs**. It omits only the informational folio-unlock hook from the
[full combined observer](combined-wait.md). The actual request-generation,
member-report, original-bio, vector, queued-wake and scheduler proofs remain.
Its functional qualification does not establish lower runtime cost; the
[separate three-arm comparison](compact-wait-cost.md) measures that question.
No persistent observer or new storage policy is installed.

Nine positive controls account for 129 request generations, 148 selected
members, seven multi-bio requests and 13 changed-generation address reuses.
All 20 observed blocked segments have actual vector and request-report
dependencies. Selected physical input totals 23,658,496 reported bytes. Those
counts describe this functional collection; they are not performance samples
or pooled totals from earlier runs. Native large/partial folios, nonzero
initial iterators, mixed membership, partial/error/requeue and broader wake
interleavings remain open.

## What is omitted

The full source logs selected folio_unlock calls, including calls that do not
wake the selected task. That hook never established a complete unlock census.
The exact wait proof instead comes from the separately matched queued folio,
its actual membership in the original bio's vector array, request reports and
the selected task's switch/wake chain.

The compact BPF source includes the frozen full source. A checked loader
derivation disables autoload of exactly `unlock_call`, removes exactly its
attachment name and requires 28 distinct owned program IDs. It retains all
13 pending-context maps and the bounded request-history registry. The full
observer's existing replacement/disabled hooks remain unchanged. Its ABI,
layout, source-header and callback-identity checks remain prerequisites.

The new `bc250-compact-wait-diagnostic` kind has an explicit
`unlock_hook_loaded=false` field. Its [reader](../analysis/compact_wait.py)
rejects any stage 12 unlock record, projects the remaining records into the
unchanged full reader and marks both unlock counts **unavailable (null)**.
It does not report an observed zero or waive the full reader's request,
vector, scheduler, transport, status or pending-context failures. The
[structural schema](../bench/compact-wait.schema.json) is only the first check;
the strict reader is mandatory.

## Evidence and controls

Offline projection of 100 retained full-observer captures removed 76,800 of
100,542 records, or 76.386%, while preserving all 120 causal edges and every
other validation result. All 15 available raw captures from the earlier
16-control qualification were also projected, preserving their positive and
negative verdicts. These are deliberate offline transformations of unchanged
original records, not newly collected compact traces or latency evidence.

New native collection then repeats the complete plain/encoded x buffered/
mapped x cold/warm matrix, same-inode different-open rejection, record-cap
incompleteness, forced-exit cleanup, serialized cold request recycling and
disabled callback/issue/folio/vector proof controls. Each missing proof still
fails quality despite correct worker contents. Warm cases submit no data I/O.
Native captures contain no omitted unlock events. The exact full-qualified
read-worker binary is reused for the final compact qualification.

The initial attempt passed its first 11 individual controls but failed the
global-state equality guard. Scheduled maintenance overlapped that run; its
exact initial state delta was not recorded, so the cause is not asserted more
precisely. The attempt remains unqualified. A new runner records before/after
global state and reuses the exact reference worker; the second collection
passes all 16 controls with identical global snapshots. Results are not pooled.

The parent retains memory, CPU, swap, tasks, runtime, private-mount and free-
space bounds. Only disposable fixture pages are evicted. Captures keep the
4 MiB ring, three-second duration and 50,000-record cap. All owned probes
detach, fixture contents and frozen references verify, and the working
installation remains unchanged. Suspend wake remains unsupported and was not
attempted. The [public evidence](evidence/stage1-compact-wait.json) contains
only minimal non-identifying totals; detailed machine records stay local.

The full Linux suite passes 302 tests, including strict compact-format and
three-arm ordering/failure checks. Stage 1 and the complete ten-stage goal
remain open. This diagnostic is measurement infrastructure, not a new
accelerator or proof of whole-application critical paths.
