# Stage 1 workload and instrumentation worklist

Status: **in progress; suite not frozen and no Stage 1 speed result yet**.
Stage 0's [starting-environment gate](evidence/stage0-gate.json) passed within its
recorded scope. The full [ten-stage roadmap](DEVELOPMENT_PLAN.md) remains active.
This stage measures system-wide behavior; it does not introduce game-specific
tuning, launch options or a per-title prefetch profile.

## First observed instrumentation limit

The [read-only capability probe](evidence/stage1-trace-features.json) runs on the
current physical kernel and records actual tracepoint field declarations,
offsets, sizes and format hashes. It enables no events and checks that observed
global tracer/clock state stays unchanged. The [fresh opening baseline](evidence/stage1-opening-baseline.json)
records the real device mapping, CPU/GPU memory limits, thermals and policy.

`block_rq_issue` and `block_rq_complete` have device, sector and length fields,
but no shared request identifier in their formatted event payload. Identical
or overlapping sectors, partial completion, merges and requeues make naive
issue/completion pairing ambiguous. Issuing PID/context also does not establish
foreground ownership through asynchronous filesystem work. Do not report a
critical-path latency or foreground stall from these fields alone.

BTF, bpftool, clang and gcc are present. perf, bpftrace and trace-cmd are absent.
Relevant Btrfs/zstd decompression and readahead functions are exposed in the
available function list, but that is not proof of a supported probe ABI or a
successful attachment. The initial observer below validates request identity through the running
kernel's raw tracepoint ABI. Partial completion/requeue handling and
orphan/lost-event interpretation still need broader qualification.
Keep all maps/buffers/time bounded, avoid persistent pins, and preserve unrelated
tracing. Application dependency attribution remains an additional requirement.

## Suite contract to freeze before comparisons

| Domain | Required scenario | Endpoint and state still to qualify |
| --- | --- | --- |
| System/application loading | Representative executable and library loading, plus an interactive application | Usable-state marker; fixed package tree and CPU/GPU policy |
| Game loading | Representative installed titles and distinct asset formats | Repeatable menu/scene marker; fixed runtime/shader/save state |
| Asset streaming | Reproducible traversal or replay with frame-time capture | Fixed route/replay, streaming interval and long-frame events |
| Controls | Compressible and already compressed/incompressible data | Distinguish storage, decompression and memory/cache limits |

An earlier PRAGMATA title-screen procedure exists privately, but its old results
are not promoted into this new frozen suite. Its title-screen endpoint is not
an asset-streaming benchmark. Audit the installed workload inventory, backups
and usable-state markers before choosing the final suite or aggregate weights.

For each workload, freeze input hashes, version, endpoint definition, timeouts,
launch/stop procedure, background activity rules, cache state and run ordering.
Distinguish asset-cold/runtime-warm from a cold system boot and warm repeated
execution. Verify residency where supported; do not label cache eviction as
SSD power-state evidence. Avoid a global page-cache reset on the working OS.

Power-only B0/B1 comparisons must use equivalent resets of the same frozen
layout. B1/B2 compare independently verified copies; incidental allocation
differences must be recorded. Account for loop/outer-filesystem effects when
using the prepared userspace images. Keep physical conversion writes, metadata
growth and lost sharing separate from logical maintenance budget charges.

## Remaining Stage 1 work

1. Freeze the concrete workload matrix, weights and regression thresholds from
   the roadmap; validate usable-state/frame markers and cache conditions.
2. Add the versioned runner and anonymized event/result schema under `bench/`,
   with interfering activity, environment drift and run order recorded.
3. Qualify request timing, queue/merge/requeue behavior, faults, filesystem reads,
   readahead and decompression attribution where the actual ABI supports them.
4. Measure tracing overhead against uninstrumented trials before relying on
   instrumented results. An event-format inventory measures no overhead.
5. Run controlled B0/B1/B2 trials and build `analysis/` reports with uncertainty,
   storage-critical waiting and alternative CPU/RAM/GPU bottlenecks separated.

The stage gate remains open. No accelerator architecture is selected from the
feature inventory, historical synthetic throughput or an ambiguous disk trace.

## Initial request-identity qualification

The [temporary request observer](request-tracing.md) now passes five bounded cases on the real kernel: idle, 2,048 serial reads, 8,192 overlapping same-location reads, an explicitly incomplete cap, and cleanup after forced exit. Known-read counts and bytes match exactly with no ring loss; fixture residency remains zero before/after the accepted controls. This supplies request-identity evidence rather than sector matching. The first control failure is retained and documented. Tracing overhead, partial/requeue/error paths, foreground dependency attribution and the frozen application matrix remain open.

## Frozen observer overhead screen

The [two-batch calibration](trace-overhead.md) retains all 86 trials and fails the prespecified serial-read screen. The fixed extension estimates +4.460% elapsed-time overhead (exploratory 95% interval +2.191% to +6.706%); three whole-window capture flags also remain disqualifying. Read bytes match and ring loss is zero, so those flags are not presented as proven read transport loss. The concurrent pilot control alone passes. Keep the observer opt-in, preserve these separate batches, qualify a distinct batched-consumption variant and compare it under a new frozen contract. No accelerator improvement or Stage 1 gate pass follows from this measurement. The Linux suite now passes 127 tests.

## Batched observer decision

The [distinct batching variant](batched-tracing.md) passes seven transport checks, including early final drain and visible ring overflow. Its 75-trial blocked comparison on one physical fixture shows no demonstrated overhead benefit and has only 18 valid blocks, below the frozen 20. Preserve the negative decision. Qualify the zero-byte/flush lifecycle and measure probe cost before another observer change, while freezing concrete application workloads and endpoints. No existing strict verdict is retroactively changed.

## Application selection and first operational endpoint

The [workload endpoint record](workload-endpoints.md) now pins installed application/game versions and observed asset suffixes, plus a tentative seven-scenario mix before new performance comparisons. The complete suite is still unfrozen. Three final-source Konsole launches each receive a valid cursor reply through the owned child's PTY and close normally; this qualifies a terminal operational marker, not first composited frame, cold-cache state or acceleration. An offline audit of all five strict failed comparison windows finds 11 flagged zero-byte flush records and no flagged reads. The 11 unmatched completion callbacks still lack operation/cause attribution, so existing verdicts remain unchanged. The Linux suite passes 134 tests.

## Second initial application marker

The [private Firefox endpoint](browser-endpoint.md) passes three final-source functional launches. Its fixed local page reports complete load, browser-visible state, image/font readiness, a scripted handler and two advancing animation callbacks; marker receipt is the endpoint. It does not prove first displayed frame, trusted input or cold-cache behavior. Each browser uses a fresh private HOME/profile in loopback-only IP networking; owned cgroup cleanup succeeds after SIGTERM. Selection v2 preserves all tentative weights/candidates while recording this status. Complete inputs, cache procedures, package/game/replay markers and attribution remain open. The Linux suite passes 137 tests.

## Partial copied-input cache qualification

The [separate file audit and copied-set probe](application-inputs.md) observes 508 regular `/usr` files and qualifies cold/warm data residency for 507 independent copies, with one privileged helper explicitly left as shared host context. The original PTY-ready helper works in both states; the controller verifies every read-only copied inode through the owned process root. This is a partial file-set cache primitive, not complete application cold state, a metadata-equivalent OS baseline or a speed result. Shared context, input closure, wrapper cost and the other workload domains remain open. The Linux suite passes 140 tests.

[Native selected-input qualification](native-application-inputs.md) preserves 530 files and selected ownership/permissions/xattrs/link relations, verifies copied paths through the owned process root, and exercises the original setgid helper with private session-accounting files in cold/warm data states. A controlled counterexample confirms nonowner mincore residency masking; a root observer measures only private copies. Normal close leaves no view processes. The Linux suite passes 144 tests. This partial fixture is not complete application input closure, a full OS baseline or speed evidence. Foreground cgroup bounds and wrapper cost remain unqualified.

## Firefox candidates and fresh seeds

The [separate Firefox audit](browser-inputs.md) passes two final-source functional launches with identical six-node initial private seeds. It records 395 host-resolvable regular `/usr` candidates (730,717,601 bytes), plus explicit runtime and nested sandbox setup context. These path strings are not verified cross-namespace file identities. The candidate set exceeds the previous 512 MiB corpus bound; a 1 GiB private construction limit is proposed but not applied. Cold-cache Firefox, complete closure, wrapper cost and profile durability remain unqualified. The suite now passes 148 Linux tests.

## Controlled mapping identity

Four native [mapping-reference controls](mapped-identity.md) now distinguish the actual mapped object from its process-root and host pathname views. Raw maps device/inode identity collides across two private Btrfs subvolumes; a pinned mapping reference correctly rejects the wrong host alias. The initial raw-field method remains failed. This read-only primitive uses a privileged observer and unprivileged private workers; its controlled qualification is separate from the later Firefox observation. Complete input closure and performance remain open. The original milestone passed 152 Linux tests.

## Scoped Firefox mapping observer

The [temporary root observer](browser-identity.md) now samples two functional launches, with 15 processes across three mount namespaces each. It verifies 209 host objects against pinned mapping references, while 172 also have matching process-root views. Six proc-fdinfo roots explain the remaining recorded view limitation; those aliases stay unresolved. Five live UID/scope/nonce/schema/replay requests are rejected, browser main capabilities remain zero, and finish verifies browser cleanup. The unchanged audit still has incomplete closure and no cache/performance qualification. All 157 Linux tests and four native identity controls pass.

## Selected native Firefox file data

The [independent native fixture](native-browser-inputs.md) now preserves 423 selected files and metadata, verifies every read-only binding through the main root, and observes 200 mapped copies in each of 15-process/three-namespace captures. Selected copied data starts at zero resident bytes for cold and 733,818,880 page-rounded resident bytes for warm. A root-mount switch and writable per-process proc controls preserve user-namespace availability; sysctls remain read-only and sandbox fallback causes refusal. Two earlier attempts are rejected. This remains selected-file data control, not complete browser cold state, layout-equivalent B0/B1/B2 or performance. The suite passes 162 Linux tests.

## Signed private package update

The [native offline fixture](package-update.md) passes a mismatched-signature rejection and three verified tzdata upgrades from identical old-package snapshots. All 1,887 payload nodes, the local package database, updated timezone query and guest-only syncfs endpoint verify. Only the private new archive/signature data is conditioned cold/warm/cold (0/331,776/0 resident bytes); whole-OS cache state, scripts/dependency transitions, obsolete-file removal, wrapper cost and performance remain unqualified. [Selection v3](../bench/workload-selection-v3.json) records this scope and the existing selected application-file controls while preserving every candidate and tentative weight. The full suite is still unfrozen. The Linux suite passes 169 tests.

## Native flush lifecycle evidence

The [six-probe diagnostic](request-lifecycle.md) now reproduces separate internal device-flush issue/completion pairs and zero-payload consumed software sequences without device issue on the running kernel. A 256-read control accounts exactly; two eight-update synchronization windows each show eight of both flush-related classes with no unexplained completion patterns or transport loss. This is identity-level evidence for a mechanism, not attribution of historical orphan counts or foreground work. Original quality rules and failed overhead verdicts remain unchanged. Static helper-call inspection motivates a separate shared-disk-lookup variant, which still needs transport and overhead qualification. The suite passes 179 Linux tests.

## Shared disk-lookup observer outcome

The [isolated callback change](shared-disk-tracing.md) removes two compiled kernel-read helper sites per callback while preserving original scope, identity, timestamps, flags and loader source. Seven transport cases pass. A frozen 75-trial off/original/shared comparison gives +2.311% shared-versus-off overhead and -1.075% shared-versus-original elapsed time, with the relative interval crossing zero. Only 18/24 blocks qualify and strict capture failures remain, so neither observer passes the full screen and the new variant is not promoted. All 50 instrumented worker windows account exactly, without rewriting whole-capture rules. Next, implement and qualify explicit flush-sequence identity handling, then assess further callback-cost changes if needed. The Linux suite passes 183 tests.

## Lifecycle-aware v2 measurement protocol

The [separate v2 observer](trace-v2.md) now keeps anonymous ordinary/device-flush/software-sequence classes with positive pointer or entry/return/completion proof. All ten final native controls pass, including exact original-size read windows and deliberate removal of each proof mechanism; missing proof remains a quality failure. Raw flags remain visible, v1 files/results stay unchanged, and unfinished contexts remain disqualifying. The shared atomic helper passes both host orders and 10,000 concurrent pairs, while actual BPF completion-before-return and broader interleavings remain unexercised. A distinct structural schema and semantic reader accompany 195 Linux tests. Next freeze a new v2 overhead comparison; this does not pass Stage 1 or establish an accelerator gain.

## V2 synthetic overhead screen passes

The [fixed 100-trial calibration](trace-v2-overhead.md) passes both prespecified screens: 22/24 valid serial pairs give +0.389% overhead (exploratory 95% interval -1.677% to +2.475%); 23/24 concurrent pairs give +2.052% (-0.796% to +4.267%). All 50 instrumented trials account exactly and pass stream quality, including three proven internal flushes and three proven software sequences with raw flags retained. Three environmental pair exclusions remain visible. The minimum 20-pair, 3% point and 5% upper limits are unchanged; no repeat or pooling. This qualifies the two synthetic controls, not application overhead or the full Stage 1 gate. The Linux suite passes 200 tests. Next instrument real workload endpoints and establish wrapper/attribution cost while extending broader callback controls.


The [native application capture integration](application-trace-v2.md) now
passes one cold and one warm Konsole launch with the unchanged selected-input
fixture and endpoint. Both whole-device captures cover the full trials and pass
stream quality, including 17 proven internal flushes and 17 proven software
sequences. No loss, unresolved context or remaining owned process is accepted.
The suite passes 207 Linux tests; application overhead and foreground
critical-path attribution remain open. No accelerator gain is claimed.

The [fixed native Konsole tracing-cost experiment](application-trace-cost.md) passes both prespecified selected-application cost screens. All 100 planned launches, 50 captures and pair exclusions are retained. This estimates incremental tracing cost within the selected fixture; absolute wrapper cost, general application overhead and foreground attribution remain open. The suite passes 216 Linux tests. No accelerator comparison or default promotion follows.
