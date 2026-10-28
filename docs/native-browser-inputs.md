# Stage 1 selected native Firefox input/cache fixture

Status: the final native fixture passes two functional launches with independent
copied inputs, zero/fully resident selected file-data controls, working nested
user namespaces and no recorded sandbox-fallback warnings. This is partial
cache/input qualification, not a whole-application cold state, full OS baseline
or performance comparison. Stage 1 remains open.

## Corpus and metadata scope

`bench/native_browser_inputs.py` consumes the checked [Firefox audit](browser-inputs.md)
and private [mapping-reference captures](browser-identity.md). It refuses changed
audit manifests, source identities/content and capture digests. The selected
set includes the audited regular `/usr` and `/etc` candidates, observed font
caches and the font configuration/link targets needed to reproduce that context.
It checks 197 audited paths against prior actual mapping-reference identities.
Other audited path candidates remain explicitly short of complete identity closure.

The new root-owned corpus contains 423 regular files, 732,783,557 logical bytes
and 563 selected file/directory/link nodes. GNU tar preserves numeric owner/group,
mode, ACLs/xattrs, regular-file mtime, symlinks and hardlink relations within the
selected set. Before/after inventories verify selected content and metadata.
Independent inodes and FIEMAP checks reject data-extent sharing with originals.
Selected directories are not a complete copied filesystem tree.

Directory timestamps, ctime, outside-set hardlinks, filesystem-specific inode
flags and physical allocation/compression layout are outside this equivalence
claim. Ordinary extraction creates a new layout. These files are not yet the
roadmap's qualified B0/B1/B2 application baselines.

The per-corpus bound is now **1 GiB**, recorded for this fixture because Firefox's
audited candidate set exceeds the earlier 512 MiB native-terminal bound. The
72 GiB free-space floor remains; the lab also requires at least 7 GiB available
memory before construction. Each attempt retains both its data corpus and tar
archive plus logs/metadata. Retained attempts add space/writes. This does not
expand or reset the production 512 MiB/pass or 2 GiB/day maintenance budgets,
and it is not a physical NAND-write measurement.

## Private native root with working browser sandbox prerequisites

Setup uses a new mount/network namespace and a read-only root view. Copied
regular files are bound read-only at their ordinary paths; the copied font
configuration directory preserves its links. A separate private HOME/profile,
temporary directories, existing desktop runtime/IPC and devices are available
to the unprivileged browser. Loopback is the only IP interface, with no default
route. Existing desktop services and filesystem metadata caches remain context.

The first chroot-based attempt passed file-cache/marker checks but blocked user
namespace creation. Firefox reported a namespace error and Glycin reported
sandbox fallback. That attempt is **rejected for qualification**, even though
its earlier harness result file said passed. Its files/logs remain intact.

Linux's [user-namespace creation code](https://github.com/torvalds/linux/blob/master/kernel/user_namespace.c)
rejects callers in a chroot whose root differs from their mount namespace's
root. A tiny helper now switches the private namespace's root mount using
`pivot_root` and detaches the old root there; the [Linux manual](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
documents that operation. The host's root mount is outside this private namespace.

A second attempt then failed before browser launch: read-only procfs prevented
writing the new namespace's UID map. Minimal native controls isolated both
restrictions without launching Firefox or duplicating its corpus:

| Private view | Per-process proc controls | User-namespace probe |
| --- | --- | --- |
| chroot | Read-only | Refused with EPERM |
| Root-mount switch | Read-only | UID-map open refused with EROFS |
| Root-mount switch | Writable; proc sysctls read-only | Passes |

The final fixture restores normal per-process proc controls inside the private
view while keeping `/proc/sys` and the sysrq trigger read-only. It requires the
unprivileged namespace probe to succeed and rejects browser/decoder sandbox
fallback warnings. Both final browser logs are empty. These prerequisites and
logs do not constitute a complete sandbox-security or environment-equivalence
qualification; no sandbox preference is disabled and no global sysctl changes.

## Cache and mapping checks

The root backend accepts only the fixed UID, trial unit, nonce, controller and
seven ordered phases. Requests contain no selected PID/path. Only private
copies receive per-file eviction or warming. Root residency observation avoids
the previously demonstrated nonowner mincore masking. Original file caches and
global caches are not evicted.

| Condition | Selected data resident before endpoint | After endpoint/cleanup | Mapping observation |
| --- | ---: | ---: | --- |
| Selected file data cold | 0 / 733,818,880 page-rounded bytes | 588,185,600 bytes | 200 mapped copies verified; zero selected original references |
| Selected file data warm | 733,818,880 / 733,818,880 bytes | 733,818,880 bytes | Same checks pass |

Each capture samples 15 processes across three mount namespaces. The actual
main executable is identified by its pinned descriptor identity, without
blindly translating a displayed path prefix. Every supported mapping reference
is checked against selected original identities; any selected original causes
refusal even under another displayed pathname. Missing references never count
as verified copies. All 423 selected read-only bindings also verify through
the main process's root at readiness, in addition to setup-time checks.

The two launches use identical fresh private profile seeds and the unchanged
functional Firefox endpoint source. Cleanup uses the endpoint's owned-group
termination, then the backend requires only the controller to remain. No
additional namespace cleanup signals or leftover view processes were needed.
Graceful Firefox quit/profile durability remain unqualified.

Residency totals are page-rounded per selected entry; they are not demanded
bytes, physical NVMe reads, SSD-cache state or proof of drive power-state entry.
Post-launch residency includes readahead, generated-loader and controller work.
Mappings are sampled, not atomic. Unobserved/transient reads, broker IPC,
generated files, external desktop services and complete input closure remain open.

## Budgets, validation and next work

The root builder/observer unit is bounded to 2 GiB memory, no swap, two CPUs'
quota, 64 tasks and 360 seconds; its actual memory/CPU/swap constraints and
private mount propagation are checked. A separate foreground unit has 3 GiB,
no swap, 512 tasks and 180 seconds, with no requested CPU quota. These ceilings
are additive, with a possible combined 5 GiB charge. No equal-RAM performance
comparison or complete resource-cost accounting is claimed.

All 162 Linux tests pass. New negative cases reject original references,
incorrect selected identities, unsafe source paths and sandbox-fallback logs;
an unavailable reference cannot qualify a copy. Syntax checks and C helper
compilation pass. Seven installed hashes, original boot configuration, active
power/timer, 5000 us setting and daily quota history verify. [Reviewed evidence](evidence/stage1-native-browser-inputs.json)
retains the final source hashes, conditions and rejected attempts.

On the authorized lab host, use fresh output directories:

```sh
sudo python3 -B bench/native_browser_inputs.py run --uid 1000 \
  --audit /absolute/owned-lab/browser-audit \
  --identity /absolute/owned-lab/browser-identity-captures \
  --output /absolute/owned-lab/new-native-browser \
  --desktop-output /absolute/owned-lab/new-native-browser-desktop
```

Next, qualify repeatability, remaining input/reset/cache dependencies and wrapper
cost before policy comparisons. Continue private package-update and reproducible
game/streaming fixtures plus request-observer lifecycle/overhead/attribution.
This fixture does not complete the Stage 1 gate or the full ten-stage goal.
