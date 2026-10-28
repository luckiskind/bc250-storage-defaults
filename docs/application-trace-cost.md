# Stage 1: incremental tracing cost on native Konsole

Status: the fixed experiment **passes both prespecified selected-application cost screens**. All 100 planned launches and
every exclusion/capture outcome are retained. This compares off/v2 inside the
same selected native fixture. Absolute wrapper cost, complete input/context
closure, foreground attribution and the complete Stage 1 gate remain open.
There is no accelerator or B0/B1/B2 comparison.

## Frozen comparison

`bench/measure_application_trace_cost.py` reuses the verified root-owned private
corpus from the [native input qualification](native-application-inputs.md)
through a new mount namespace and new read-only bindings. The same original
copied inodes serve both conditions; there is no reconstruction between pairs.
Selected content/metadata, copied native helpers, qualified v2 sources/binaries
and kernel are checked. Session accounting uses new private empty files. GUI
and controller use the original real UID/groups and zero controller capabilities.

The unchanged endpoint is the owned helper's operational Konsole PTY marker,
not a displayed frame. Every launch gets fresh XDG config/data/cache directories
and the same private HOME context. The native process-root binding check and
original setgid session helper still run on every trial. The original endpoint
elapsed time is the measurement; attach/startup, the common idle interval,
capture drain, serialization and normal cleanup are outside that endpoint.
Full trial envelopes and existing before/after snapshots remain separate.

Seed 254 fixes 24 off/v2 pairs for each of selected-data-cold and
selected-data-warm. Each scenario has 12 off-first and 12 v2-first pairs, shuffled
before collection, plus one off/v2 warmup pair: 100 launches, 96 measured and
four warmups. The contract/order are written and fsynced before collection.
Cold means zero resident pages in the 530 selected copied files. Warm means all
222,560,256 page-rounded bytes resident. A root observer conditions and checks
those fixed inputs before every trial, rechecks after observer setup, and checks
again after normal close. Host originals and global page caches are not reset.
This is not host-cold, full input closure or confirmed controller power state.

A private socket accepts only the exact view-controller PID/UID, nonce and 204
planned phase messages. Caller-selected paths/devices/settings are rejected.
Only v2 conditions attach the six previously qualified programs. A two-second
overall slot and 250 ms post-setup quiet interval apply to both conditions.
V2 captures must cover the complete owned trial and pass strict semantic quality.
Unknown/lost/unclosed contexts are not waived. A failed measured or warmup
capture prevents a pass even if its pair is environmentally excluded.

Whole-pair environmental exclusions are pre-launch CPU busy above 10%, more
than 128 KiB pre-launch device I/O, less than 2 GiB available memory, recorded CPU
policy drift or parent-cgroup throttling during the broad trial interval. The
minimum is 20 valid pairs per scenario; the point overhead must be at most 3%
and the exploratory paired 95% upper bound at most 5%. Timed device I/O cannot
yet be split into foreground and background, so no unsupported timed-I/O
subtraction/exclusion is applied. Exclusions are recorded, never replaced by
new trials. Serial dependence and all sources of environmental drift remain
unproven; these exploratory intervals are not general application guarantees.

## Result

| Selected data state | Valid pairs | Geometric tracing overhead | Exploratory paired 95% interval | Screen |
| --- | ---: | ---: | --- | --- |
| selected-data-cold | 22/24 | +0.362% | -0.027% to +0.718% | pass |
| selected-data-warm | 23/24 | -0.062% | -0.499% to +0.364% | pass |

Positive values mean longer PTY-ready latency with tracing. All per-launch
elapsed times, capture reviews, cache states and pair exclusions appear in
[the reviewed aggregate](evidence/stage1-application-trace-cost.json).
No failed historical observer result is reinterpreted or pooled with this run.
No retry was used to choose a favorable outcome.

50 of 50 instrumented streams pass semantic quality. Across all captures,
404 internal device flushes and 404 consumed software sequences have
positive lifecycle proof with raw flags retained. Every launch passes its native
PTY/normal-close checks and original private session record check. All 530
read-only bindings are verified through the owned process root each time.
Root collection progress and trace serialization are deferred; the unchanged
endpoint still writes its own private diagnostic/config files during trials.
This is not an assertion that the measurement produces no disk writes.

## Resource and qualification limits

The parent has 2 GiB memory, no swap, 200% CPU quota, 128 tasks and a 900-second
lifetime. Each loader has two 8192-entry maps, a 4 MiB ring and a 200,000-record
cap. Retained raw output is bounded at 128 MiB for the collection. These control
the collector: as previously recorded, Konsole can move into user-manager
scopes and the whole foreground application's cgroup bounds remain unqualified.
The 72 GiB free-space floor holds. Reusing the existing corpus avoids another
corpus/archive copy; endpoint artifacts and ordinary filesystem writeback still
add lab writes. They are separate from the preserved production ledger.

Independent post-collection review reconstructs all 50 instrumented capture
reviews from private raw traces and original endpoint/envelope records, checks
all 100 endpoint times and cache preconditions, recomputes the complete paired
summary and separately cross-checks geometric ratios. Windows recomputation
from public rows agrees within 1e-12 floating-point tolerance. Sources, observer binaries, selected corpus and copied
helpers verify after collection. The cache socket is removed and no owned view
processes or programs remain. The working installation's seven hashes, original
boot configuration, 5000 us policy, active/enabled services and quota charges
verify. The regression suite passes **216 Linux tests**.

The result covers incremental v2 tracing cost in this fixed selected Konsole
fixture. It does not quantify the fixture's own distortion versus a normal
launch, other applications, decompression attribution, first displayed frames,
tail streaming behavior, physical energy or system-wide accelerator gain.
Suspend wake is unsupported per owner; no sleep or reboot is attempted.

## Reproduction and next gate

Requires the matching prior native input and ten-case v2 qualifications, the
existing KDE Wayland session and their dependencies. Outputs must be new
directories. Keep the desktop path short for the Unix socket length limit.

```sh
sudo python3 bench/measure_application_trace_cost.py run \
  --native-qualified /absolute/private-lab/qualified-native-terminal \
  --qualified /absolute/private-lab/qualified-v2 \
  --output /absolute/private-lab/new-application-cost \
  --desktop-output /absolute/private-lab/new-cost-desktop
```

Next qualify filesystem/page-fault/decompression dependencies, measure absolute fixture cost and extend comparable cost checks to the remaining real workloads.
The [full workload gate](workloads.md) stays open; the tracer remains opt-in.
