# Stage 1 partial application inputs and copied-file cache control

Status: one private Konsole file audit and two final-source copied-file cache
conditions pass. This establishes a bounded cache-control primitive for an
audited file set. It does **not** complete application input closure, qualify a
full OS baseline, establish whole-application cold state or measure acceleration.

## Separate input audit

`bench/application_inputs.py` runs a separate, instrumented Konsole launch with
private HOME/settings/data/cache. strace 7.2 follows pathname syscalls and file
mappings; read/write payload syscalls are not recorded. The original PTY-ready
helper still works and the test window closes normally. Traced timing is not
used as performance evidence.

The audit combines successful decoded file-descriptor paths and executable
paths with mappings from the owned application/helper ancestry at readiness.
Failed opens and arbitrary exec argument strings do not become successful file
inputs. It hashes supported regular `/usr` and `/etc` candidates with before/
after identity checks, retaining full paths, hashes and raw traces privately.
Public evidence contains only aggregate counts, source/tool hashes and limits.

Observed: 13 trace files, 864,884 trace bytes and 596 path candidates. Of these,
508 distinct regular `/usr` files total 219,344,624 logical bytes; six distinct
regular `/etc` context files total 205,480 bytes. Other candidates include
directories, runtime/kernel state, generated private files and paths outside the
approved source classes. No escaped/deleted descriptor annotations were seen.

This is a conservative observed set, not proof of complete reads: directory
entries, failed-path decisions, transient loads, IPC, environment and unaudited
paths still require qualification. A mapping/path inventory does not establish
accessed byte ranges, critical-path dependencies or useful bytes demanded.
[Reviewed audit evidence](evidence/stage1-application-inputs.json) preserves scope.

## Independent copied set

`bench/copied_input_probe.py` consumes the checked private audit manifest. It
refuses changed source identities/content, path traversal, conflicting canonical
aliases, unknown exceptions, oversized corpora and existing outputs. Limits are
1,024 files, 512 MiB logical data, 256 MiB per file and a 64 GiB free-space floor.
Construction writes only a new private directory on Btrfs using ordinary
read/write copies; there is no reflink/copy-file-range shortcut or device format.
Each file is synced, hashed and checked for independent inode and unshared data
extents. File modes and mtimes are copied. Owner/group, all xattrs and hardlink
topology are **not** reproduced, so this is not a metadata-equivalent OS tree.

The first strict selection refused `/usr/lib/utempter/utempter`, a privileged
session-recording helper, before creating the corpus. The guard remains. A
separate explicit `--leave-shared-privileged` option allows that exact audited
helper to remain unchanged as host context; it cannot exclude an ordinary input
or an unknown path. No privileged mode is copied or stripped. Its functionality
in the private namespace is unqualified.

The resulting set has 507 files, including two empty files. The final-source
run uses the original endpoint helper unchanged. A private mount namespace
exposes each copied inode read-only at its ordinary absolute application path.
After ownership validation, the controller checks the owned process's `/proc`
root view: all 507 device/inode/size identities match the copies, all bindings
are read-only, and the process's mount namespace differs from the parent's.
The [bubblewrap documentation](https://github.com/containers/bubblewrap/blob/main/README.md)
describes these mount views. This fixture retains desktop IPC/device access;
it is not presented as a general security sandbox.

## Cache-state checks

Only copied files receive per-file eviction. `mincore` checks file-data page
residency; there is no global page-cache reset or original-file eviction.
After the cold launch, reading/hash-checking the complete copied set primes the
warm control. Fresh private application settings are used for each launch.

| Condition | Before launch: resident copied data | After endpoint/close: resident copied data | Result |
| --- | ---: | ---: | --- |
| Copied-file data cold | 0 / 220,401,664 page-rounded bytes | 182,427,648 bytes | PTY endpoint, normal close and 507 read-only bindings pass |
| Copied-file data warm | 220,401,664 / 220,401,664 bytes | 220,401,664 bytes | Same checks pass |

The two empty files have no pages and count as both zero-resident and fully
resident. Page-rounded bytes differ from logical file bytes. Post-launch
residency includes readahead and helper activity; it is not a measurement of
unique demanded bytes, physical reads or foreground critical-path waiting.

The parent mount namespace and original/copied contents remain unchanged.
Working profile hashes, original boot menu, 5000 us setting and daily quota
history still verify. The Linux suite passes 140 tests. [Final copied-set
evidence](evidence/stage1-copied-input-cache.json) retains both conditions.

An earlier copied-set prototype also passed cold/warm checks but executed extra
binding-validation code in its marker child. It is retained. The final version
moves validation to the controller, after the helper's ready timestamp, and
keeps the original child helper. Both successful private corpora remain as
separate construction artifacts. Their logical copy writes and metadata are
separate from the production maintenance ledger; the per-corpus limit is not a
total lab-write or physical NAND-write ceiling.

## Limits before performance use

The host `/etc`, runtime/IPC context, excluded helper, unaudited dependencies and
filesystem metadata remain shared or uncontrolled. Private mount setup and the
selected input environment differ from ordinary unwrapped launch. No copied-
cold/warm timing is promoted as an application improvement. Wrapper overhead,
input closure, metadata equivalence and environment repeatability must be
qualified before using a fixture for the roadmap's B0/B1/B2 comparisons.

`mincore` reports file-data residency, not SSD/controller cache or confirmed NVMe
power-state entry. These tests do not establish physical-device cold state or
change any power policy. They do not replace the separately prepared native OS
baselines or extend this result to Firefox, games or streaming.

## Reproduction and next gate

Use the observed Linux desktop user, Python 3.11+, strace, bubblewrap and the
matching source. Outputs must be new:

```sh
python3 bench/application_inputs.py audit \
  --output /absolute/owned-lab/new-terminal-input-audit
python3 bench/copied_input_probe.py run \
  --audit /absolute/owned-lab/new-terminal-input-audit \
  --output /absolute/owned-lab/new-copied-inputs \
  --leave-shared-privileged /usr/lib/utempter/utempter
```

Review the private manifest before accepting a context exception. Keep failed
attempts. Next, resolve the remaining input/context classes, preserve required
metadata in independent native application baselines and quantify wrapper cost.
Extend the audit/reset/cache method to Firefox. Private package-update and game
scene/replay/frame markers, tracer lifecycle/overhead and dependency attribution
remain part of the full Stage 1 gate.
