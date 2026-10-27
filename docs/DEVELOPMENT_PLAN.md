# BC-250 storage accelerator: sequential development plan

**Status:** active goal; Stage 0 has passed its target-specific gate; Stage 1 measurement work is underway. See [the baseline record](baseline.md) for completed checks and open gates. This document itself does not execute commands or change a machine.

**Prepared:** October 26, 2026.

**Duration and staffing:** 52 weeks, 12 senior engineers.

**Target repository:** [luckiskind/bc250-storage-defaults](https://github.com/luckiskind/bc250-storage-defaults).

**Starting release:** [v0.1.0](https://github.com/luckiskind/bc250-storage-defaults/releases/tag/v0.1.0), commit `c9ee4b2133af11e6ffb85f017c8a197997889df8`.

## 1. Destination and scope

Build an installable Linux storage accelerator that reduces storage-related waiting across applications on an unchanged BC-250. Applications should use their normal files and launch commands. The system should select useful layout, caching and read-ahead policies automatically.

The moonshot is a **50% reduction in measured storage-critical-path waiting** across a workload suite defined before optimization. Additional stretch goals are 70% fewer long storage-induced streaming pauses and 2–3 times the physical link's throughput in useful data on suitable compressible workloads. These are research targets, not current results or release promises.

The PCIe link remains hardware limited. Cold, incompressible data cannot acquire extra physical bandwidth through software. A successful implementation must recognize cases where acceleration is unhelpful and avoid introducing significant overhead.

Year-one scope includes application startup, desktop responsiveness, game loading, asset streaming, package updates and concurrent memory pressure. It excludes per-game launch tweaks, changing game asset formats, lossy transformations, bypassing access controls, SSD firmware modifications and relying on additional hardware or a remote server. GPU decompression is an optional late experiment, not a dependency.

The deliverable is one maintained package with compatibility checks, understandable status, bounded resource use, recovery instructions and reproducible evidence. Upstream submissions are desirable; upstream acceptance is not a controllable 12-month deliverable.

## 2. Starting evidence and unresolved questions

The existing prototype provides two mechanisms:

- A persistent 5000-microsecond NVMe latency-tolerance setting, qualified on the tested PNY CS2241 1TB controller at PCIe 5 GT/s ×2.
- Gradual native Btrfs repacking of eligible stable ELF binaries into verified compressed extents of at most 16 KiB.

The released repacker limits work to 512 MiB per pass and 2 GiB per UTC day, with a five-minute processing budget and a 64 GiB free-space floor. Its defaults scan system and user application roots. These are starting policies to evaluate, not assumed optimal settings for all systems.

Existing validation includes 15 isolated Linux tests, a live disposable 2 MiB fixture with matching before/after SHA-256 and 16 KiB compressed extents, and passing GitHub CI. Earlier clean measurements on a copied ELF corpus showed approximately 13–54% read-throughput gains depending on access pattern; the incompressible control did not gain. These measurements do not establish end-to-end game or desktop improvements. See the pinned release's [validation record](https://github.com/luckiskind/bc250-storage-defaults/blob/c9ee4b2133af11e6ffb85f017c8a197997889df8/VALIDATION.md).

Questions to answer before broadening deployment:

1. How often does the SSD sleep during actual workloads, and how much waiting comes from waking it?
2. Which startup and streaming delays are actually storage critical rather than CPU, GPU, shader, network or synchronization delays?
3. How much of the real working set is compressible, reusable or predictable?
4. Does smaller-extent repacking improve application latency enough to justify writes, metadata and lost sharing?
5. Can cache and layout decisions remain correct through writes, mappings, replacement, updates and crashes?
6. Can benefits survive the BC-250's actual CPU/GPU memory pressure?

## 3. Measurement contract

### Baselines

Preserve independent, reproducible baseline volumes or images. A repacked volume cannot be turned into the original layout merely by disabling the service.

| ID | Configuration | Purpose |
| --- | --- | --- |
| B0 | Recorded original storage layout and power policy | Historical reference; recreate on a dedicated test setup |
| B1 | Original layout plus the qualified 5 ms drive policy | Separate drive wake-up improvements from layout improvements |
| B2 | Fixed 16 KiB repacking plus the same drive policy | Strong existing-prototype baseline |
| BX | Candidate plus the same drive policy | Evaluate each new component against B1 and B2 |

Keep CPU policy, GPU allocation, application versions and other system settings fixed. Test drive-power changes separately. Do not count the same wake-up improvement again as a benefit of every later component.

### Workload suite

Define at least 12 scripted scenarios before selecting a winning design. Include OS/session startup, native application launches, a browser or equivalent multi-process application, multiple games with different storage patterns, repeatable asset-streaming routes, package installation/update, and a mixed foreground/background session. Include compressed archives, incompressible files, small random reads and large sequential reads. Include several tasks expected to gain little as negative controls.

Use reproducible routes, save positions or application actions as measurement fixtures. These fixtures must not alter production launch policies or require per-game optimization settings.

Separate training workloads from held-out applications, versions and access sequences. Use openly redistributable fixtures in CI; keep proprietary game data on authorized local test machines.

### Required cache conditions

Report each condition independently:

1. **Host-cold:** reboot or a documented cache-reset procedure on an isolated machine; accelerator RAM caches empty. State whether a derived on-disk cache exists. Do not claim the SSD's internal cache was necessarily cold.
2. **Repeat launch:** reproduce the interval and intervening memory use between runs.
3. **Steady-state streaming:** measure a defined sequence after startup.
4. **Memory pressure:** repeat with fixed competing CPU/GPU workloads and controlled available memory.
5. **After change:** repeat after a package update, game update, file replacement or cache invalidation.

A process restart is not sufficient evidence of a cold cache. Attribute reads to their source: ordinary page cache, compressed RAM cache, derived on-disk store or canonical filesystem.

### Metrics and accounting

| Metric | Definition and use |
| --- | --- |
| User-visible task latency | Time from a defined action to a defined usable state; primary product outcome |
| Storage-critical-path waiting | Time during which storage completion demonstrably prevents progress; do not sum overlapping waits from multiple threads |
| Long streaming pauses | Count/duration above a threshold fixed per scenario before comparison; correlate with storage evidence |
| Tail behavior | p95/p99 of sufficiently numerous comparable events; report sample counts and uncertainty |
| Useful throughput | Unique requested logical bytes delivered divided by elapsed time; identify cache hits separately |
| Read amplification | Physical device read bytes divided by unique logical bytes actually demanded, with read-ahead and metadata accounted separately |
| Decompression amplification | Logical bytes decompressed divided by useful demanded bytes |
| Maintenance cost | Physical bytes written, write rate, elapsed work, CPU time and added disk space |
| Memory cost | Resident metadata, compressed cache, decompressed pages and duplicated representations, including cgroup accounting |
| System impact | CPU time, frame times, memory/IO pressure, temperature and power/energy where trustworthy measurement is available |

The 50% stretch goal uses the ratio of total non-overlapping critical-path wait across the frozen scenario mix, with scenario weights fixed in advance. Also publish every scenario and the geometric mean of end-to-end speedups. Do not hide individual regressions behind an aggregate.

Use randomized or counterbalanced A/B order, at least ten independent repetitions per main scenario/configuration, and more if confidence intervals remain inconclusive. Collect enough streaming events to make tail claims meaningful. Reject and record runs with unrelated benchmarks, downloads, updates or thermal changes. Report excluded runs and reasons. The earlier CPU-latency-test interference must not recur unnoticed.

### Default promotion rules

These are proposed engineering thresholds to freeze in Stage 1:

- No detected content corruption, stale reads, authorization bypass, unrecoverable update failure or filesystem-semantic failure. Any such failure blocks promotion.
- A major subsystem should improve the geometric mean of end-to-end task latency by at least 5% against the stronger applicable qualified baseline, with uncertainty supporting the direction of the gain. Preserve useful narrower results as explicitly scoped experiments if this gate fails.
- No scenario may show a confirmed end-to-end regression above 3%, or p99 frame-time regression above 5%, in the default policy. Larger regressions require a working automatic bypass and renewed held-out testing.
- Measure idle power and maintenance energy; do not silently accept a higher-power policy merely because it improves latency.
- Stay within the selected memory/disk/write budgets and demonstrate prompt throttling under contention. Budget increases require a recorded tradeoff and a fresh comparison.

## 4. Team and development rhythm

| Team | Engineers | Primary ownership |
| --- | ---: | --- |
| Filesystem and kernel | 4 | Extent layout, read path, filesystem/MM interfaces, semantics |
| Cache and prediction | 3 | Compressed RAM, cost models, read-ahead, invalidation |
| Measurement and reliability | 3 | Tracing, workloads, statistical comparisons, fault injection |
| Integration and release | 2 | Packaging, compatibility, resource policy, recovery, documentation |

The plan is sequential at its acceptance gates. Teams can prepare supporting work within a stage, but a dependent subsystem cannot be promoted until its prerequisite evidence passes. Assign one accountable engineer and a reviewer from another team to each milestone.

Budget approximately 20% of capacity for integration, regressions, review and recovery. Hold a weekly evidence review and a monthly stop/continue decision. Extra compute or model output does not replace hardware runs, code review or reliability testing.

For every experiment, save its hypothesis, commit, machine manifest, data layout, cache conditions, exact invocation, results, uncertainty and decision. Record failed experiments so they are not repeated without new evidence. Keep credentials, private paths and unrelated user activity out of public artifacts.

## 5. Sequence and dependencies

| Stage | Weeks | Main result | Required predecessor |
| --- | --- | --- | --- |
| 0 | 1–2 | Recoverable, qualified baseline | Existing v0.1.0 |
| 1 | 3–6 | Trustworthy workload traces and measurements | Stage 0 |
| 2 | 7–10 | Feasibility model and architecture decision | Stage 1 |
| 3 | 11–16 | Verified adaptive native-layout prototype | Stage 2 |
| 4 | 17–22 | Better data grouping/read path, or a documented decision to omit it | Stage 3 |
| 5 | 23–30 | Correct integrated behavior through writes, updates and crashes | Stage 4 |
| 6 | 31–36 | Pressure-aware compressed file-data cache | Stage 5 |
| 7 | 37–42 | Bounded automatic prediction and system resource policy | Stage 6 |
| 8 | 43–48 | Broad validation and release candidate | Stage 7 |
| 9 | 49–52 | Shippable release and reproducibility package | Stage 8 |

Every stage below specifies ordered work and a gate. If a gate fails, take its fallback before moving on. Schedule pressure never waives correctness.

### Stage 0 — Preserve and qualify the starting system

**Weeks 1–2. Owner: integration/release, supported by reliability.**

1. Pin v0.1.0, preserve its sources/checksums and document the installed lab configuration separately from the reusable package.
2. Provision an isolated BC-250 test environment with a known-good boot path, backups and disposable test volumes. Retain the user's working installation as a reference rather than the destructive-test target.
3. Capture controller capabilities, negotiated link, kernel/filesystem versions, mount options, memory split, thermals and current power policies. Identify all actual filesystem devices instead of assuming a permanent `nvme0` naming relationship.
4. Test a fresh package installation, repeated application, removal, reboot and suspend/resume. Verify actual drive settings and service state after each transition. Test suspend/resume only on targets with functional wake support; record an unsupported target explicitly rather than attempting a known nonrecoverable sleep. The owner reports that this BC-250 has no functional suspend wake (2026-10-27), so physical resume is excluded from its compatibility claim and is not a gate for continuing development.
5. Exercise failed/partial installation, administrator edits, missing dependencies, unsupported hardware and interrupted activation in disposable environments.
6. Recreate B0/B1/B2 on separate test volumes and verify equal logical content. Record physical layout differences rather than assuming snapshots preserve an independent baseline after in-place repacking.

**Deliverables:** `docs/baseline.md`, machine manifests, installation/recovery tests, baseline image/volume recipe.

**Gate:** a clean target can be installed and recovered predictably; the drive policy restores correctly; interrupted operations retain enough state for recovery.

**Fallback:** release a reliability-only update and repair the baseline before starting new storage mechanisms.

### Stage 1 — Find the actual waiting

**Weeks 3–6. Owner: measurement/reliability.**

1. Freeze workload definitions, cache-state procedures, aggregation weights and regression thresholds.
2. Build a versioned result format and runner that records interfering activity, run order and environmental changes.
3. Add low-overhead tracing for device requests, queue/completion latency, page faults, readahead, filesystem reads and CPU decompression where the target kernel exposes suitable instrumentation. Probe features; do not assume a particular tracepoint ABI.
4. Correlate those events with application usable-state markers and frame-time events. Resolve asynchronous dependencies rather than assigning all disk-busy time to the foreground application.
5. Measure real drive idle intervals and wake-up behavior. Separate idle duration from confirmed power-state entry; document inference when direct state evidence is unavailable.
6. Run B0/B1/B2 across the suite. Measure tracing overhead by comparing instrumented and uninstrumented trials.

**Deliverables:** `bench/`, `analysis/`, `docs/workloads.md`, baseline report and an anonymized trace schema.

**Gate:** task endpoints and cache conditions reproduce reliably; attribution identifies the main bottlenecks; tracing overhead is quantified and small enough for its intended use.

**Fallback:** improve instrumentation and simplify scenarios. Do not choose an architecture from synthetic throughput alone.

### Stage 2 — Establish achievable gains and select the architecture

**Weeks 7–10. Owners: filesystem/kernel and cache/prediction.**

1. Classify observed file regions by access size, temporal reuse, compressibility, mutation frequency and sharing. Include real archives and already compressed data before expanding the ELF-only prototype.
2. Build an offline replay/model that evaluates candidate chunk sizes, compression choices, metadata costs, cache budgets and read-ahead. Include physical block rounding and decompression amplification.
3. Estimate optimistic bounds for compression-only, caching-only and prediction-only improvements. Use knowledge of future accesses only for a clearly labeled oracle bound.
4. Check the critical path against CPU decompression throughput, RAM capacity, memory bandwidth and measured device bandwidth. Include the physical cost of any duplicate on-disk representation.
5. Compare architecture candidates: extending native Btrfs behavior; an immutable compressed store on a private test mount; and a cache-only path. EROFS is an experimental read-only foundation, not an automatic replacement for a writable root filesystem.
6. Choose one primary production path and define filesystem/MM interfaces, ownership, failure boundaries and rollback. Prefer retaining native Btrfs semantics if measured gains support it. Write an architecture decision record before adding a new on-disk format.

**Deliverables:** replay/model, per-workload gain bounds, `docs/architecture.md`, architecture decision records.

**Gate:** measured working-set characteristics support an application-level benefit beyond B2, with a plausible CPU/RAM/disk budget and coherent write semantics.

**Fallback:** narrow the product to the mechanisms with evidence. If the oracle cannot approach the moonshot on the frozen suite, publish that limit and revise the target explicitly; do not redefine the suite to manufacture success.

### Stage 3 — Make native layout adaptation work on copied data

**Weeks 11–16. Owner: filesystem/kernel.**

1. Turn the current repacking primitive into a separately testable operation with explicit capability checks, bounded progress, error handling and content verification.
2. On disposable copies, sweep compression choices and extent targets across the observed workload classes. Treat requested defrag range/size as a hint until actual extents are inspected and verified.
3. Start with a deterministic classifier. Choose smaller independent compressed regions for random access, larger regions for streams, and bypass for poor compression or excessive costs.
4. Compare adaptation with the fixed 16 KiB baseline on held-out access sequences. Include metadata growth, CPU cost, initial conversion writes and subsequent update behavior.
5. Preserve conservative exclusions until each new file class passes its own content, concurrency and performance tests. Do not infer support for archives from ELF results.
6. If the desired behavior needs kernel support, prototype the smallest explicit Btrfs change on test kernels. Check normal writes and later extent coalescing as well as the immediate repack result. An offline layout is not a proven future-write policy.

**Deliverables:** adaptive-layout experiment, compatibility probes, expanded correctness fixtures and a layout-selection report.

**Gate:** the classifier improves its intended held-out workloads and obeys the global promotion rules. All layout choices preserve file bytes and supported metadata.

**Fallback:** keep the best fixed policy or disable repacking for unhelpful classes. A native kernel extension is not required merely to make the design appear more ambitious.

### Stage 4 — Reduce unnecessary reads through grouping and read-path work

**Weeks 17–22. Owner: filesystem/kernel, supported by cache/prediction.**

1. Reproduce a controlled EROFS comparison on copied fixtures and identify the measured source of any gain: compression, clustering, metadata, copying or concurrency.
2. Implement access-frequency and similarity grouping in an offline builder if Stage 2 predicts sufficient benefit. Keep dictionary dependencies and random lookup costs bounded.
3. Compare grouping with the same codec/chunk policy but without grouping. Use a test format or an explicitly supported filesystem extension; arbitrary cross-file grouping is not an existing Btrfs defrag feature.
4. Optimize the demonstrated hot path: batch metadata work, overlap reads with decompression, bound worker concurrency and remove copies only where profiling proves they matter.
5. Evaluate cold random reads, sequential reads, competing CPU/GPU work and index-memory costs. Test malformed chunks and missing dictionaries.
6. Select one implementation to integrate. If a derived image/pack path wins, document its namespace, mutation and canonical-source relationship before it leaves a private mount.

**Deliverables:** builder/read-path prototype, component ablation report, final backend decision.

**Gate:** benefit survives complete accounting against the strongest native baseline. Backend complexity and memory costs are justified by application outcomes.

**Fallback:** omit grouping or the image/pack backend and continue with qualified native layout changes. Do not maintain two competing production filesystems within the year-one budget.

### Stage 5 — Make the selected path correct through change and failure

**Weeks 23–30. Owners: filesystem/kernel and reliability.**

1. Specify the consistency model before implementation. Distinguish authoritative filesystem data from disposable derived acceleration data. Corrupt derived data may fall back to a validated canonical source; authoritative data needs filesystem recovery and backups.
2. Implement identity/version handling robust to inode reuse, rename, replacement, truncation and writes. A pathname or size/mtime check alone is not a complete coherence protocol.
3. For derived caches, coordinate invalidation with buffered writes, shared writable mappings, direct I/O and in-flight reads at an appropriate filesystem/MM boundary. Bypass unsupported operations. Filesystem notification alone is not a correctness guarantee.
4. Exercise `read`, `pread`, executable mappings, private/shared mappings, `fsync`, rename-overwrite, unlink-while-open, hardlinks, symlinks, sparse files, permissions, ACLs/xattrs, reflinks and snapshots.
5. Run package/game update fixtures, interruption during conversion, disk-full conditions, I/O faults, daemon death, cache corruption and abrupt power-loss tests on disposable storage. Add recovery for every persistent state transition.
6. Build reader-safe garbage collection for obsolete derived data and indexes, with disk-space reservation and bounded cleanup work.
7. Complete an install/upgrade/remove migration path that retains administrator edits and preserves a known-good boot option. Avoid whole-root overlay replacement as a default shortcut.

**Deliverables:** consistency specification, recovery state machine, fault/concurrency suite, integrated alpha.

**Gate:** no stale reads, content mismatches or access-control failures in the required matrix; recovery succeeds after each tested failure point; updates behave normally.

**Fallback:** retain a research-only private mount or restrict caching to demonstrably immutable objects. Do not ship a daemon that serves stale data while waiting for an asynchronous invalidation event.

### Stage 6 — Add a pressure-aware compressed cache for file data

**Weeks 31–36. Owner: cache/prediction, supported by filesystem/kernel.**

1. Use measured reuse distance to select initial cache budgets. Compare with ordinary Linux page-cache behavior under the same total RAM limit.
2. Implement a derived compressed tier for clean file data, with a hot uncompressed tier supplied by ordinary pages where practical. Add the necessary filesystem/MM integration explicitly; enabling zswap does not provide this cache.
3. Charge compressed data, indexes and transient decompression buffers to the resource budget. Measure and bound duplicate compressed/uncompressed representations.
4. Integrate invalidation with the Stage 5 protocol. Test executable mappings and reads through multiple processes. Avoid cross-user deduplication or observable cross-user cache sharing in the first release.
5. Add reclaim/shrinker behavior, concurrency limits, low-memory escape paths and protection against repeated compress/decompress thrashing. Never discard dirty authoritative data as a cache eviction.
6. Test multiple budgets and competing GPU workloads. Start conservatively; expand only if end-to-end gains survive memory-pressure testing.

**Deliverables:** compressed file-cache prototype, memory accounting, pressure/reclaim tests and equal-RAM comparison.

**Gate:** gains persist against ordinary caching at equal total memory, with correct invalidation, bounded reclaim latency and no confirmed foreground regressions above the contract.

**Fallback:** disable the compressed tier and retain ordinary page caching plus the earlier layout/read-path improvements. Keep the successful resource accounting and measurements.

### Stage 7 — Add automatic prediction and a unified resource policy

**Weeks 37–42. Owner: cache/prediction; integration owns policy controls.**

1. Implement simple sequence/recency predictors first. Train on local access history with retention limits; avoid requiring application-specific configuration.
2. Compare with no prediction and existing read-ahead. Distinguish demand misses saved from reads merely shifted earlier and bytes fetched but never used.
3. Admit a speculative read only when its estimated value exceeds IO, CPU, memory and eviction costs. Cap speculative bytes and queue depth.
4. Prioritize demand reads over prediction and maintenance. Reduce or stop optional work when foreground IO, memory pressure, CPU load or frame-time evidence indicates contention. Measure the response time rather than assuming idle priority is sufficient.
5. Detect prediction failure after updates, scene changes and new applications. Decay old history and automatically fall back to ordinary reads.
6. Combine layout, cache and prediction in an ablation matrix: each alone, useful pairs and the full system. Stop optimizations whose benefits disappear in combination.

**Deliverables:** automatic predictor, policy/status interface, held-out workload report and integrated beta.

**Gate:** prediction reduces task latency or storage-linked pauses on held-out sequences while respecting resource/regression limits. The combined system beats its strongest simpler configuration.

**Fallback:** ship the simpler configuration with prediction disabled by default. Retain prediction as an opt-in experiment only if its narrower scope is clear.

### Stage 8 — Validate breadth, reliability and operating cost

**Weeks 43–48. Owner: measurement/reliability.**

1. Freeze the feature set. Run the full suite against B1, B2 and the integrated candidate, with independent cold/repeat/streaming/pressure/update reports.
2. Test at least three BC-250 units if available and additional controller/SSD variants only behind explicit capability qualification. Document the limits of a single-machine result if the hardware fleet is unavailable.
3. Run concurrent package updates, foreground applications, snapshots, low-space conditions, permission changes and sustained memory pressure. Include workloads whose data is already compressed or unpredictable.
4. Complete repeated reboot/update cycles, suspend/resume on supported targets, and at least a 14-day soak with a recorded activity mix. Inspect data hashes, kernel warnings, memory growth, maintenance writes and SSD health counters throughout.
5. Have engineers who did not implement the mechanism reproduce installation, removal, corruption handling and a performance subset from the documentation alone.
6. Determine which targets were met, which mechanisms should be default, and which features remain unsupported. Prepare a release candidate only after blockers are resolved.

**Deliverables:** qualification matrix, complete benchmark report, soak/recovery report, release candidate.

**Gate:** correctness and recovery pass; default regression budgets hold; results reproduce independently. A missed stretch target is reported honestly and does not justify relaxing correctness.

**Fallback:** release only the qualified subset or extend the alpha. Do not label a kernel/filesystem change stable solely because synthetic checksums and CI passed.

### Stage 9 — Ship and make the result maintainable

**Weeks 49–52. Owner: integration/release, with all teams reviewing.**

1. Package the qualified configuration with one apply command, read-only preflight, status, stop-maintenance and remove/restore commands. Clearly distinguish stopping acceleration from reconstructing an old layout.
2. Pin supported kernel interfaces and formats. Ship compatibility probes, tested upgrade paths, debug bundles with redaction and a documented recovery boot path.
3. Publish source, build instructions, checksums, benchmark fixtures, aggregation methods and negative results. Make hardware-specific tests distinct from ordinary CI.
4. Submit small, independently useful upstream patches where appropriate; preserve attribution and dependency licenses. Keep unsupported research branches separate from release defaults.
5. Define support ownership, a regression-triage process, format/version policy and a six-month maintenance backlog.

**Deliverables:** versioned release, reproducibility package, support matrix and maintainer handoff.

**Gate:** a fresh qualified machine can be installed, checked, updated and recovered using the published instructions, and release claims match the evidence.

## 6. Explicit stop rules and scope controls

| Finding | Required response |
| --- | --- |
| Corruption, stale data or access-control bypass | Disable the affected mechanism, preserve evidence and repair correctness before further promotion |
| Workload mostly consumes cold incompressible bytes | Bypass recompression; evaluate only demonstrated caching, prediction or overhead reductions |
| New layout saves bytes but makes application latency worse | Reject it for that class; do not use compression ratio as the product metric |
| Repacking loses too much sharing or causes repeated rewrites | Skip shared/mutable classes, reduce work, or keep the feature opt-in |
| Compressed cache loses to ordinary caching at equal RAM | Remove it from the default path |
| Predictor evicts useful data or competes with foreground IO | Tighten admission or disable prediction |
| GPU decompression reduces rendering performance | Stop the branch; CPU path remains the supported baseline |
| A new filesystem or format exceeds the integration budget | Prefer the best qualified existing-filesystem path; retain the branch as research |
| Gains disappear outside the training set | Fix the model or narrow the support claim; do not add per-game exceptions to conceal failure |

GPU work, elaborate learned models, global dictionaries and whole-root image conversion require evidence from earlier stages and a bounded experiment budget. None is a prerequisite for shipping a useful result.

## 7. First ten changes, in implementation order

Each change should be reviewable and should leave the last qualified path usable. The paths below are proposed additions, not claims about files already present.

1. **Baseline record:** add `docs/baseline.md` and pin the existing release, machine facts and known gaps.
2. **Recovery tests:** extend disposable install/undo and interrupted-activation tests; add a fresh-install recipe.
3. **Workload contract:** add `docs/workloads.md`, scenario endpoints, cache-state procedures and a result schema.
4. **Manifest capture:** add a read-only machine/environment recorder with private-data redaction.
5. **Repeatable runner:** add workload orchestration, randomized ordering and interference detection.
6. **Tracing probe:** add optional low-overhead tracing and an overhead calibration test.
7. **Attribution report:** correlate storage events with task/streaming markers and label uncertainty.
8. **Baseline publication:** publish B0/B1/B2 results with complete per-scenario outcomes.
9. **Offline feasibility model:** add chunk/compression/reuse analysis with oracle bounds and equal-resource comparisons.
10. **Architecture decision:** select the primary backend and record why alternatives were rejected; only then start the new data path.

Do not begin by expanding the root service's write scope, changing every file's compression or reserving a large RAM cache. The first development milestone is a trustworthy answer to where the machine waits and which mechanism could remove that wait.

## 8. Evidence package required for each stage

Use a consistent stage record with these fields:

```text
Stage / owner / reviewer:
Hypothesis and expected mechanism:
Source commit and dependency versions:
Machine and filesystem manifest:
Baseline(s), workloads and cache conditions:
Run order, repetitions and excluded runs:
Application outcomes and uncertainty:
Physical IO, CPU, memory, disk-space and write costs:
Correctness, concurrency and recovery results:
Known limitations and unsupported cases:
Decision: promote / revise / stop:
Next prerequisite that is now satisfied:
```

Public reports should contain the data needed to assess a claim while excluding credentials, private file paths, unrelated activity and proprietary application content. Keep detailed authorized traces locally when they cannot be redistributed.

## 9. Research foundations and boundaries

- **Current project evidence:** the pinned [v0.1.0 validation record](https://github.com/luckiskind/bc250-storage-defaults/blob/c9ee4b2133af11e6ffb85f017c8a197997889df8/VALIDATION.md) anchors baseline comparisons. It does not establish general application speedups.
- **Btrfs layout risk:** the [Btrfs defragmentation documentation](https://btrfs.readthedocs.io/en/latest/Defragmentation.html) states that defragmentation can break extent sharing and increase space consumption. Stage 3 must account for that cost and Stage 0 must preserve independent baselines.
- **Compressed read-only foundation:** the [Linux EROFS documentation](https://docs.kernel.org/filesystems/erofs.html) describes compressed image storage and read/decompression features. It supports an experimental comparison in Stages 2–4; writable desktop semantics still need separate engineering and qualification.
- **Similarity and access-frequency grouping:** [RubikFS, FAST '26](https://www.usenix.org/conference/fast26/presentation/huang) motivates testing grouped chunks. Its read-only-image results are research evidence for a mechanism, not a forecast of BC-250 game gains.
- **Compressed-cache boundary:** [Linux zswap documentation](https://docs.kernel.org/admin-guide/mm/zswap.html) describes caching swap pages. A coherent compressed cache for clean file data is a separate proposed component with its own filesystem/MM integration and correctness requirements.

Review the target kernel's actual interfaces at the relevant stage. Documentation and research describe possibilities; feature probing and measurements determine what this project can safely support.
