# Stage 1 native metadata and private session-accounting fixture

Status: the selected native Konsole input fixture passes cold/warm data-cache
checks. It preserves selected ownership, mode, xattrs, regular-file mtimes,
symlinks and hardlink relations within the selected set. This is partial input
qualification. Stage 1 remains open; there is no application speed result.

## What changed

The [earlier copied-file fixture](application-inputs.md) left a privileged
session-accounting helper as host context and did not preserve owner/group,
xattrs or hardlink relations. `bench/native_application_inputs.py` now builds
a separate root-owned corpus from the checked audit manifest. GNU tar preserves
numeric ownership, permissions, ACLs and xattrs. Before/after inventories check
all selected nodes and content. File data uses independent, unshared extents.
Directory timestamps, ctime, inode numbers and hardlinks outside the selected
set are not reproduced. This is not a complete OS baseline.

The set contains 530 regular files, 221,429,906 logical bytes and 661 selected
file/directory/symlink nodes. It includes the audited `/usr` files, selected
font caches, font configuration and explicit `/etc` context, plus the unchanged
terminal helper. The 512 MiB data bound and 72 GiB host free-space floor apply
to each construction. Retained attempts are additional lab writes and space;
these limits are not physical NAND-write ceilings or the production ledger.

The private root view exposes copied regular files read-only at their usual
absolute paths. After the original PTY helper reports readiness, the controller
verifies every copied device/inode/size and read-only binding through that owned
process's root view. The marker still denotes an operational PTY, not a first
composited frame. Extra validation is outside its ready timestamp; wrapper cost
has not been qualified for performance comparisons.

## Preserve native helper behavior without host session writes

The copied original session helper retains its setgid mode and actual group.
Mount setup is privileged; the GUI/controller then runs with the desktop user's
real IDs and supplementary groups, with effective/permitted/ambient capabilities
zero. `NoNewPrivs` remains zero to permit the original helper's setgid semantics.
No capabilities are granted to the GUI and copied file modes are not weakened.

Private empty `utmp` and `wtmp` files replace session-accounting paths inside the
view. A small ordinary C checker verifies exactly one USER_PROCESS record for
the owned terminal and user while the helper is alive, in each cache condition.
It reports counts only. Both terminals close normally; no processes remain in
the unique test mount namespace. Failure cleanup targets only that namespace,
uses process descriptors and rechecks membership before signaling. Its guard
refuses the controller's own namespace.

Root construction/controller work has a 2 GiB memory limit, no swap allowance,
200% CPU quota and a five-minute lifetime. Konsole can move into scopes owned by
the existing user manager. **Those limits are not qualified bounds on the whole
foreground application.** The view retains device access, desktop IPC, runtime
services and the user's cgroup context. It is a measurement fixture with explicit
shared context, not a general security sandbox. Runtime/IPC state, remaining
paths, filesystem metadata cache and complete input closure remain unqualified.

## Correct cache observation for root-owned inputs

Linux may deliberately report all pages resident when the caller does not own a
file and cannot open it for writing. The upstream [mincore implementation](https://github.com/torvalds/linux/blob/master/mm/mincore.c)
documents that restriction and fills the result with ones in that case. This
must not be mistaken for evidence that a root-owned fixture is actually warm.

A private 1 MiB root-owned mode-0444 counterexample on this installed kernel
confirmed it: root measured zero resident pages, the ordinary non-owner measured
all 1 MiB resident, and root still measured zero afterward. No production file
was evicted. This supports the diagnosis of the first native attempt's cache
guard failure, whose nested diagnostic was not retained; it does not reconstruct
the exact missing exception. That failed artifact remains intact.

The revised fixture keeps residency observation in the root controller. A private
Unix socket admits only the exact dropped-privilege controller PID/UID and four
ordered nonce-bearing requests: cold-before, cold-after, warm-before, warm-after.
There is no caller-selected path. The observer can evict/warm only the fixed
private corpus. The client also verifies the server's root UID and expected PID.
Negative tests reject wrong identities, nonces and phases before file access.

| Condition | Resident copied data before | Resident copied data after close | Checks |
| --- | ---: | ---: | --- |
| File data cold | 0 / 222,560,256 page-rounded bytes | 176,189,440 bytes | PTY, normal close, private session record, all 530 read-only bindings pass |
| File data warm | 222,560,256 / 222,560,256 bytes | 222,560,256 bytes | Same checks pass |

Two empty files count as both zero-resident and fully resident. Post-launch
residency includes readahead/helper activity and is not demanded bytes, physical
NVMe reads, device-cache state or critical-path waiting. The original and copied
selected contents/metadata remain unchanged. The working installation's seven
file hashes, original boot configuration, 5000 us setting and quota history verify.
The Linux suite passes 144 tests. [Reviewed evidence](evidence/stage1-native-application-inputs.json)
retains the final result, earlier attempts and the counterexample.

## Reproduction and next prerequisites

Requires the matching Linux desktop session/audit, root construction privileges,
GNU tar, a C compiler, systemd and mount-setattr support. Review the selected
private inputs first. Outputs must be new directories under the authorized lab.

```sh
sudo python3 bench/native_application_inputs.py run \
  --audit /absolute/owned-lab/terminal-input-audit \
  --output /absolute/owned-lab/new-native-inputs \
  --desktop-output /absolute/owned-lab/new-native-desktop \
  --uid 1000
```

The root corpus is private; the separate desktop output belongs to the selected
user. Raw paths, per-file hashes, session files and desktop logs stay private.
No production defaults, boot files or power policy change. No suspend is tried:
the owner reports that this BC-250 has no functional suspend wake.

Next, finish input/context closure and repeatability, quantify wrapper cost,
extend auditing/reset/cache controls to Firefox, and qualify private package
updates and reproducible game/streaming markers. Observer flush/orphan lifecycle,
overhead and foreground dependency attribution remain prerequisites for Stage 1.


The [native application capture integration](application-trace-v2.md) now
passes one cold and one warm Konsole launch with the unchanged selected-input
fixture and endpoint. Both whole-device captures cover the full trials and pass
stream quality, including 17 proven internal flushes and 17 proven software
sequences. No loss, unresolved context or remaining owned process is accepted.
The suite passes 207 Linux tests; application overhead and foreground
critical-path attribution remain open. No accelerator gain is claimed.
