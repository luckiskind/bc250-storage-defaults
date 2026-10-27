# Private OS provenance across remounts

Development qualification tooling only. The production worker and drive policy
are unchanged by this milestone. Stage 0 remains open.

## Problem and repair

The OS builder originally recorded the guest directory's device/inode pair.
Btrfs device numbers can change across remounts, so a preserved guest could fail
that check after restart. New construction markers use format 2 and record both
the workspace and guest directory using the installer's existing Btrfs UUID and
opaque export-handle identity. The old pair remains an audit field. A normal
private-user ownership shift does not replace the directory and is permitted.

Marker reads reject final symlinks, extra hardlinks, foreign ownership, group or
other write permission, oversized input and unsupported formats. Both persistent
identities must be valid and match. A lookup failure stops the operation. This
does not establish safety against concurrent host-root directory replacement.

## Existing private workspaces

Before restarting the test host, an existing format-1 workspace can be migrated
only while its original guest device/inode check still matches:

```sh
sudo python3 tools/prepare_test_os.py migrate-identity \
  --workspace /absolute/private-lab/test-os
```

The command verifies the private seed against the pinned SHA-256, records the
actual directory identities, saves an exact read-only copy of the original
marker, synchronizes that backup and atomically commits the new marker. It
preserves the earlier fields and is idempotent. Failed preparation or backups
remain available for inspection. The command retains the existing Linux/root,
private-directory, Btrfs and 72 GiB host-free-space requirements.

An absent or mismatched original ownership record is refused before migration.
Do not edit saved device numbers or use matching file contents to bypass this
check. Preserve the old workspace; create a separately authenticated fresh tree
if the old ownership cannot be established. This migration applies to private
OS construction records, not interrupted installer transaction journals.

## Native qualification

The [recorded result](evidence/stage0-workspace-provenance.json) passes six cases
on two newly created regular Btrfs image files in a private mount namespace:

| Case | Verified result |
| --- | --- |
| Authenticated legacy migration | Exact backup, preserved fields, repeat changes nothing |
| Actual device-number change after remount | Format-2 record accepted without rewriting it |
| Unmigrated legacy record after that change | Migration refused; marker/backups unchanged |
| Byte-identical guest-directory replacement | Refused; original and replacement preserved |
| Snapshot with equal inode number/content | Refused; original remains accepted |
| Normal private-user UID shift | Persistent identity accepted; payload unchanged |

Run the optional native test with root, Btrfs tools and at least 72 GiB free:

```sh
sudo unshare --mount --propagation private \
  python3 tests/remount_test_os.py --scratch /absolute/private-lab-parent \
  --seed-archive /absolute/private-lab/existing-os/archlinux-bootstrap-2026.10.01-x86_64.tar.zst
```

Only two new 1 GiB regular image files are formatted. Images and evidence are
retained, and all test mounts are unmounted. The seed is authenticated but never
executed by this test. Unit tests substitute identities on ordinary CI
filesystems; the native test uses actual Btrfs and Linux handle operations.

Two actual existing lab OS trees migrated with exact marker backups, unchanged
guest-root metadata and idempotent repeats. An earlier incomplete build lacking
the original guest identity was refused and preserved. A separate fresh pinned
seed extraction created a format-2 marker and passed an actual offline nspawn
probe after ownership shifted to a private user range. Its dependency preparation
remains incomplete; it is not a new qualified workload baseline.

The current isolated Linux suite passes 109 tests. Earlier baseline, VM and
native-trial evidence retains its own source versions and scope; this tooling
change does not retrospectively rerun those experiments.

## Worker signature audit

The unchanged worker uses device/inode/size/mtime/ctime as a conservative cache
key, rather than as permission to recover a transaction. A changed device
number causes eligibility checks to run again. Already-small compressed files
are checked before any budget reservation or repacking. The separate durable
daily ledger is not keyed by device number and is not reset by this mismatch.

A previously verified layout miss or unhelpful-compression result may be
reconsidered after such a mismatch. Its work is still bounded by normal pass,
day, time and free-space limits. This static audit identifies an efficiency
limitation, not a demonstrated content or quota failure; persistent worker-cache
keys remain a later measured policy decision. No performance benefit is inferred.

## Physical boot preparation and remaining gate

The same evidence records preservation of 28 existing boot files (673,807,093
bytes), checked archive contents and 154 kernel/initramfs references in the
existing Limine configuration. Its 128-character suffixes matched BLAKE2b-512,
consistent with [Limine's configuration documentation](https://github.com/limine-bootloader/limine/blob/trunk/CONFIG.md#paths).
The boot source hashes were unchanged through the copy. A second private archive
on the Windows PC has the same SHA-256. A read-only root-subvolume reference
contains the running kernel's modules; a separate SQLite backup passes integrity
checking. Private manifests, boot archives and raw directory identities are not
included in this repository.

This is preservation, not an independently booted recovery environment. The root
reference is on the same SSD, excludes separate home/other subvolumes and is not
a complete off-device system backup. Never restore an older maintenance ledger
to regain an already-consumed daily allowance. No bootloader settings, firmware
variables, working services or power settings were changed. The first private
preparation attempt stopped at an incorrect SHA-512 verifier; its empty output
directory was retained, and the corrected BLAKE2b verifier used a new directory.

Actual physical boot/reboot/resume, a demonstrated recovery path, physical-write
and lost-sharing accounting, and the Stage 1 workload/measurement gates remain
open. No hardware power-loss test or new throughput comparison was performed.
