# Stage 1 signed offline package-update fixture

This fixture qualifies a repeatable private update endpoint on the BC-250's
native kernel. It does not measure an accelerator benefit or qualify a full
system upgrade. Stage 1 remains open.

## Actual transaction and endpoint

`bench/package_update.py` uses two existing, signed CachyOS cache archives:
`tzdata` 2026c-1.1 and 2026d-1.1, architecture `x86_64_v3`. These are real
packages, not generated packages that bypass normal transaction processing.
The newer archive is 324,153 bytes; its detached signature is 438 bytes.
The installed newer payload contains 1,887 nodes: 1,054 regular files, 760
hardlinks and 73 directories. Its regular-file logical bytes total 1,771,906.
The update changes 51 regular-file contents; this version pair removes no
payload paths, so deletion behavior is not qualified by this transaction.

The guest runs its own `pacman -U` with a private database, log, configuration,
cache and verification keyring. The configuration requires trusted signatures
for local archives and has no repositories. Dependency checking and the
existing guest's ordinary transaction hooks remain enabled. This particular
package has no required dependencies or install script and adds no hooks.

Two monotonic markers distinguish package-manager return from the verified
endpoint. The latter requires the exact new version, the package manager's
detailed file check and local database check, independent full payload content/
mode/owner/link verification, an updated timezone query, and successful
`sync -f /` inside the guest. That final synchronization targets the private
filesystem, rather than requesting a global host sync. This is a verified
transaction boundary, not proof of physical power-loss persistence.

The [pacman manual](https://man.archlinux.org/man/pacman.8.en) distinguishes
package-file checks from database consistency checks. It also warns that its
alternate-root option is unsuitable for mounted guests. Here the package
manager executes inside its native userspace container instead. The
[configuration manual](https://man.archlinux.org/man/pacman.conf.5.en) defines
the local-file signature policy used for this offline transaction.

## Isolation, reset and resources

Only a newly created regular sparse 80 GiB image is formatted. Its inner
Btrfs filesystem has a different UUID from the host. It is mounted privately
with zstd:1, noatime, nosuid and nodev. A previously authenticated, protected
minimal OS archive supplies the userspace. The seed retains its prepared
shifted ownership; no full host OS or user-data copy is substituted.

The builder verifies its private mount namespace and resource limits. The
guest has separate user, PID, mount and network namespaces; only loopback is
present and the physical NVMe device is absent. A nonce and actual filesystem
UUID guard every guest operation. Only the private inputs/plan/program are
bound read-only, with a distinct writable result directory for each run.

`systemd-nspawn --keep-unit --register=no` retains the guest within the bounded
parent service, rather than allocating an independent machine scope. The
[systemd documentation](https://www.freedesktop.org/software/systemd/man/latest/systemd-nspawn.html)
specifies that combination. The shared ceiling is 2 GiB memory, zero swap,
200% CPU, 128 tasks and 360 seconds; each container invocation also has a
120-second controller deadline. A 72 GiB host free-space floor remains.
The image's sparse virtual capacity is not reserved host space. Retained
images, copied archives and logs add lab writes/space; they neither reset nor
expand the production maintenance quota and are not a NAND-write measurement.

The old package is installed and fully verified before freezing a read-only
base subvolume. A negative snapshot pairs the old archive with the newer
archive's detached signature. It must fail specifically on PGP verification,
with the private package database and old payload unchanged. Only public
verification-ring and trust-database files are copied from the host's package
trust store; host secret key files are never copied or published.

Three writable snapshots then reset to the same verified old database and
payload. Snapshots share extents inside one filesystem. They qualify this
reset procedure, not independent physical layouts or B0/B1/B2 equivalence.
The final run requires unchanged host package database, timezone payload,
package log, protected seed archive and fixture source; it unmounts and seals
the retained image after successful completion.

## Cache controls and interpretation

The order is fixed in advance: archive data cold, warm, cold. Only the two
private newer archive/signature files receive per-file eviction or warming.
Root residency observation requires exactly zero or all 331,776 page-rounded
bytes before the corresponding trial. The guest consumes a precomputed,
authenticated payload manifest; it must not hash/read the archives before
starting the transaction and invalidate the cold condition. Setup and final
validation read the original archives but never evict their caches.

The guest OS, package database, existing payload, keyring, filesystem metadata,
SSD internal cache and host context are not controlled cold states. The
marker deliberately includes verification work in addition to the native
transaction; its cost has not been separated. Three checks are functional
qualification, not statistical sampling or a cold/warm speed comparison.
No throughput, latency improvement or system-wide benefit is claimed.

The machine-readable [evidence](evidence/stage1-package-update.json) records
final checks and earlier attempts. The first attempt retained an installed
private old package but failed its version query because a transaction-only
option was passed to query mode. The second passed functional/cache checks;
the final source repeats them with explicit shared parent-unit containment.

The fixture covers one small metadata-heavy, data-only package. Repository
refresh/download, scripts, dependency transitions, obsolete-file removal,
multi-package upgrades, interrupted updates, disk-full behavior, full OS cache
reset, wrapper cost and foreground dependency attribution remain open.
Candidate weights and membership are unchanged; the full workload suite is
not frozen.
