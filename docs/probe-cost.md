# Stage 1: owned-probe runtime accounting

The fixed **16-slot** diagnostic completes with all accounting and causal
checks passed. All **328 Linux tests** pass. It profiles the exact qualified
[handoff BPF binary](handoff-wait.md), without rebuilding or changing probes.
Eight work slots and eight paired idle slots each have an intended one-second
accounting hold inside the ordinary three-second capture.

Across the work slots, the kernel records **3.907 ms** of aggregate owned
program runtime and **18,122 invocations**. The idle slots record **1.724 ms**
and **14,046 invocations**. These are sums of recorded program runtimes,
**not exclusive CPU time, foreground-only cost or endpoint overhead**. They
include profiling overhead and unrelated activity. Work-minus-idle is not an
estimate of instrumentation-free application cost.

| Program | Work recorded runtime | Work invocations | Idle recorded runtime | Idle invocations |
| --- | ---: | ---: | ---: | ---: |
| `fw_sched_switch` | 0.771 ms | 5,958 | 0.701 ms | 5,560 |
| `fw_sched_waking` | 0.491 ms | 3,012 | 0.447 ms | 2,802 |
| `fw_sched_wakeup` | 0.368 ms | 3,012 | 0.337 ms | 2,802 |
| `map_enter` | 0.301 ms | 1,118 | 0.026 ms | 278 |
| `pr_issue` | 0.255 ms | 173 | 0.030 ms | 238 |

The three scheduler probes contribute **41.7% of work-slot recorded program
runtime** and dominate idle-slot accounting. This motivates investigating
their context-lookup path. It does not establish that they cause a matching
share of application delay, nor predict a speedup from changing them.

## Scope of accounting

Installed declarations and the running/installed kernel image identity are
checked before enabling accounting. Static review of that exact image anchors
the descriptor enable/release path. The
[upstream implementation](https://raw.githubusercontent.com/torvalds/linux/v7.2/kernel/bpf/syscall.c)
uses a shared runtime-accounting reference; releasing its descriptor decrements
that reference. Accounting may therefore affect other BPF programs while the
owned descriptor is open. Only owned-program records are retained.

No sysctl is written and no counter is reset. A sysctl value of zero is not
a census of other processes' statistics descriptors. Cleanup closes only owned
references, preserves unrelated owners and checks the unchanged setting.
Native controls verify bad-descriptor refusal and closure after killing an
owned statistics-holder process. The statistics descriptor is close-on-exec;
the controller opens it after the existing observer/worker start and calibration.

The small compiled helper checks full program-info length, identity, type,
translated length and its own structure size. It records before/after clock
bounds for each owned program-info call. The analysis refuses unknown fields,
rounded or overflowed values, resets, identity/ABI changes and uncovered
endpoints. Recursion misses remain visible and disqualify accounting quality;
none occur here.

Program and cross-CPU snapshots are not simultaneous. Runtime accounting can
include nesting/interruption; summing programs is not a unique CPU-time
partition. Observation, statistics and dispatch overhead are not calibrated
away. The profiler is diagnostic only, with no latency comparison or default
promotion.

## Fixed experiment and validation

The schedule has two blocks per plain/encoded × buffered/mapped condition.
Each condition has both work-before-idle and idle-before-work order. Blocks
and per-program snapshot orders are shuffled with seed 256 and durably frozen
before collection. No extension or sample pooling occurs.

The work uses the exact qualified inherited-descriptor worker at its unchanged
2 MiB read-plus-content-hash endpoint. New private files have equal content,
verified encoding and no shared extents. Every slot evicts/checks only its
private file data. This does not establish cold filesystem metadata or SSD
internal caches. Idle workers remain at the handshake during profiling; their
content check runs only after observer detach and lies outside the counters.

Every owned program's measurement encloses the work endpoint. Independent
review also finds all selected causal records inside the common inner
accounting interval. Eight active captures retain nine actual vector-backed
blocked segments. Sixteen raw captures and all counter pairs replay exactly;
92 independent lower-bound checks verify relevant invocation counters against
selected emitted events. All causal checks pass; no quality failure is removed.

The experiment retains the existing 2 GiB memory, zero swap, two-CPU quota,
128-task, private mount namespace and free-space guards. Runtime is bounded
at 180 seconds, with a 128 MiB retained-file cap. The 28 program references and
statistics descriptor close before observer detach. Tracing inventory, installed
profile, boot configuration, power setting and quota history verify unchanged.

Only [reviewed aggregate results](evidence/stage1-probe-cost.json) are public.
Program IDs, absolute clocks, raw captures, detailed image records and per-file
hashes remain private. The prior [cost-screen failures](compact-wait-cost.md)
remain unchanged. Native early overlap and full application attribution remain
unqualified.

## Next candidate

Investigate kernel task-local storage for scheduler context lookup, first
checking actual helper, map and tracepoint support on this kernel. This is a
research candidate, not a supported implementation or measured improvement.
It must preserve all selected tasks, asynchronous edges, entry clocks,
pending-context accounting, exit handling and proof-removal refusals. A
single-task pointer shortcut cannot silently discard other selected threads.

If a candidate loads and passes independent functional controls, run a new
frozen contemporaneous cost comparison. Fewer lookups, fewer records or a
lower diagnostic runtime alone cannot qualify application acceleration.
