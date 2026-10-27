# Stage 1 mapped-file identity across private root views

Status: four final-source native controls pass. The observer identifies the
actual mapped file through a pinned mapping reference, checks the process-root
view, and accepts a host pathname only when it names that same live object.
This is a read-only identity primitive for controlled fixtures. The later [Firefox observer](browser-identity.md) connects it to the owned audit;
complete input recording remains unqualified.

## Why pathname and raw maps identities are insufficient

The [Firefox audit](browser-inputs.md) observes nested sandbox setup paths and
ordinary host-resolvable path candidates. A name does not establish the same
object in different root/mount views. The first proposed check compared the
device/inode columns from `/proc/PID/maps` directly with `stat` on the rooted
path. A real Btrfs control rejected a valid match: the maps device was 33, while
`stat` reported device 52 for that very file. This failed method is retained.

Upstream [mapping output code](https://github.com/torvalds/linux/blob/master/fs/proc/task_mmu.c)
uses the inode's superblock device. That is not a universal substitute for a
filesystem's reported `stat` device. More decisively, the final native controls
created two private Btrfs subvolumes with distinct files that had identical raw
maps device/inode values. The raw fields cannot distinguish these objects.
The source provides the mechanism; the target's controlled observation is the
evidence for this BC-250. No claim is made about every custom-kernel detail.

## The revised identity check

`bench/mapped_identity.py` requires its caller to supply an owned-process
predicate. It checks that predicate, pins the process with a PID descriptor,
opens its proc directory/root, and rejects an exited process. It reads the maps
file through EOF within a 1 MiB bound and retains individual mapping ranges;
rows are not deduplicated solely by the unsafe raw device/inode pair.

For each supported regular-file candidate, it follows the corresponding
`/proc/PID/map_files/start-end` reference with `O_PATH`. The returned descriptor
pins the mapping's actual file object while the observer checks its metadata.
It then resolves the pathname inside the pinned process root using `openat2`
with `RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS`. This keeps absolute symlinks
inside that root and rejects proc-style magic-link escapes. The [kernel UAPI](https://github.com/torvalds/linux/blob/master/include/uapi/linux/openat2.h)
defines those resolution controls. A small C helper supplies the syscall without
hard-coding an architecture-specific syscall number in Python.

The rooted descriptor must have the same live `stat` device/inode identity as
the mapping reference. Only then is the observer's ordinary host pathname
compared with that pinned reference. A different or unavailable host object is
not accepted as an alias. Device/inode equality is used while descriptors pin
the objects, not as a persistent identity across reboot, replacement or remount.
The check does not hash mapped data or prove content stability/permissions.

Mapping references require special privilege: upstream [proc link handling](https://github.com/torvalds/linux/blob/master/fs/proc/base.c)
restricts following them to the initial user namespace's administrative or
checkpoint/restore capability. The native controls use an initial-namespace
root observer and unprivileged worker processes. No capability is given to a
GUI application. If a mapping reference cannot be opened, the result remains
`mapping_reference_unavailable`; there is no pathname/raw-maps fallback that
can silently accept an alias.

## Final native controls

Each worker maps a 4 KiB private file behind its own read-only root view. The
controller validates Unix-socket UID, nonce and ancestry before observing it.
The worker waits at a private barrier, then exits normally when released.

| Case | Mapping versus observer's same pathname | Result |
| --- | --- | --- |
| Ordinary file, unchanged view | Same object | Host alias accepted |
| Another ordinary file bound at that path | Different object | Host alias rejected; correct view object identified |
| File in the first private Btrfs subvolume | Same object | Host alias accepted |
| File from the second subvolume bound at the first path | Different objects with identical raw maps device/inode values | Host alias rejected; correct view object identified |

All four final-source cases pass, all workers exit normally, the parent mount
namespace is unchanged and all four control contents remain correct. The two
private subvolumes and all earlier attempts remain as artifacts. The observer
unit has a 512 MiB memory limit, no swap allowance, one CPU's quota, 64-task
limit and 60-second lifetime. Data writes are four 4 KiB files per successful
construction, plus metadata/compiler/log artifacts; retained attempts are extra
space/writes outside the production maintenance ledger. No production file,
drive policy, boot configuration or global cache is modified.

The first test exposed a separate proc-reader bug: a large read returned only
the first chunk, so a later mapping was missed. A private diagnostic confirmed
multiple chunks; the bounded reader now continues through EOF. Early control
attempts using raw maps identity fail and remain failed. A later control passed
the mapping-reference design; the final source also closes a reference if its
metadata lookup fails. None of these runs is performance evidence.

## Sampling and support boundaries

The [proc documentation](https://docs.kernel.org/filesystems/proc.html) explains
that mapping walks can race with process changes. This observer does not stop
or enter processes and does not claim an atomic snapshot. It samples maps
before/after the per-object checks, marks disappearing ranges as changed,
checks the mount-namespace identifier again and rechecks process liveness and
ownership. This cannot prove that every mapping stayed unchanged between
observations. Transient loads, non-mapped reads, failed paths, directories,
IPC and mutable file semantics remain unqualified.

Deleted, escaped, zero-inode and noncanonical path candidates are explicitly
skipped; nonregular view objects are classified separately. Complete maps
input is bounded to 1 MiB and 8,192 objects per process. Private reports retain
paths, mapping ranges, device/inode values and namespace/process identifiers.
The public evidence contains aggregate outcomes and source hashes only.

The Linux suite passes 152 tests, including rooted absolute symlinks, magic-link
refusal, unsupported names, ownership refusal, live self mappings and a forced
mapping-reference denial. A denial must remain unresolved even when ordinary
maps fields would appear to match. The unchanged Firefox audit retains its
earlier source hash and its incomplete-identity verdict. The separate root
observer adds a host/reference relation even when the process-root view is
unavailable, without changing that unresolved view status. [Reviewed native evidence](evidence/stage1-mapped-identity.json)
does not promote that browser verdict.

## Reproduction and next prerequisite

On the authorized Btrfs lab host, use a new output directory:

```sh
sudo python3 -B bench/qualify_mapped_identity.py run \
  --uid 1000 --output /absolute/owned-lab/new-mapping-controls
```

This creates new disposable subvolumes; it does not remove earlier evidence.
The GUI user's identity is used only for the private workers. The [bounded Firefox integration](browser-identity.md) now passes its recorded
process-scope checks and snapshots. Next, use verified mapping associations for
selected native browser inputs while retaining unresolved root aliases and
qualifying remaining file/IPC dependencies. Cold-cache Firefox, complete closure, wrapper overhead and the other
Stage 1 workloads/attribution remain open. The full goal remains active.
