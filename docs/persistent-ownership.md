# Recovery across Btrfs mount-order changes

The development installer now records persistent Btrfs file identities in version 2 transaction journals. This repairs a reproduced recovery refusal after an unchanged filesystem is mounted under a different device number. It does not change the repacking algorithm, its budget, drive power policy or installed payloads.

## Reproduced failure

The earlier journal saved `st_dev` and the inode number. In two newly created sparse regular Btrfs images, mounting the second image between unmounting and remounting the first changed the first image's device number from 136 to 138. Its filesystem UUID, inode and file bytes stayed the same. The old installer then refused both staging cleanup and removal recovery as ownership changes. It preserved the files and journals, but could not complete recovery. The [original reproduction](evidence/stage0-mount-identity-reproduction.json) pins that source version.

## Persistent identity and refusal rules

For new transactions, the installer obtains an opaque Linux export handle from the already-open file descriptor using `name_to_handle_at` with `AT_EMPTY_PATH`. It pairs that handle and its type with the full Btrfs filesystem UUID returned by `BTRFS_IOC_FS_INFO`. The returned mount ID is deliberately excluded. The [Linux interface](https://man7.org/linux/man-pages/man2/open_by_handle_at.2.html) supports opaque-handle comparison and warns that mount IDs are not persistent. The [Btrfs implementation](https://github.com/torvalds/linux/blob/master/fs/btrfs/export.c) includes inode, subvolume and generation in the handle. [Btrfs documentation](https://btrfs.readthedocs.io/en/latest/Subvolumes.html) explains why the inode alone is insufficient across subvolumes.

Content, mode and ownership checks remain mandatory. A live staging/destination hardlink pair is still checked during installation rollback. Complete staging artifacts and removal targets must also match their recorded persistent identity. Replacing both hardlink names with byte-identical new files does not bypass that check. A snapshot with the same inode numbers and contents has a different subvolume identity and is also refused. The installer opens fingerprinted paths without following a final symlink and obtains identity and content through the same descriptor. Lookup failures stop recovery; there is no content-only or device-number fallback for version 2 journals.

Existing version 1 journals retain their original strict device/inode checks. They are not silently upgraded from current contents. If a legacy journal's device identity no longer matches, preserve the journal/files and matching checkout for investigation. Do not edit its saved device number, delete it, or manufacture a version 2 identity to make recovery continue. The new format prevents this failure for future transactions; it does not retroactively prove ownership for a legacy interrupted operation.

## Qualification

The [native mount-order matrix](evidence/stage0-persistent-ownership.json) runs the actual installer and its recovery code in a private mount namespace. It formats only two newly created 1 GiB sparse regular image files under a new root-private directory. Each scenario uses a private Btrfs subvolume. The source payloads and state are separate from the working host installation. Service/controller operations are simulated; the worker's disposable Btrfs content/layout self-test is real.

| Scenario | Required result after actual installer SIGKILL and remount |
| --- | --- |
| Published, uncommitted payload | Roll back owned files and complete the journal |
| Committed manifest, cleanup interrupted | Preserve all seven files and finish cleanup |
| Removal interrupted after its first deletion | Finish removing the remaining owned files |
| Both hardlink names replaced with identical new bytes | Refuse before service operations; preserve every file and journal |
| Subvolume replaced by a snapshot | Refuse despite equal inode/content; preserve every file and journal |
| Legacy published transaction | Refuse the changed device identity without upgrading the journal |
| Legacy removal transaction | Refuse the changed device identity without deleting remaining files |

Every case must demonstrate an actual device-number change and an unchanged original persistent identity across remount. Successful recovery must be idempotent. Every refusal must leave all present targets, ownership witnesses and pending journal bytes unchanged, with zero service calls. Test images and failed state are retained for inspection; test mounts are removed before exit. A checkpoint deadline bounds each installer child.

Run on the authorized Linux test host with Btrfs tools and at least 72 GiB free in the scratch filesystem:

```sh
sudo unshare --mount --propagation private \
  python3 tests/remount_install.py --scratch /absolute/private-lab-parent
```

The scratch parent must exist, contain no symlink components and not be writable by other users. The command creates a new directory and prints the private result path. It never formats a host block-device path, changes live startup units, or reboots the host. Unit tests substitute identities for temporary CI filesystems; this native matrix exercises the actual Btrfs ioctl and Linux handle lookup.

A fresh [selected installer VM cache-loss case](evidence/stage0-persistent-ownership-cache-vm.json) also passes with the repaired transaction module and the unchanged calibrated disk model. It drops **32,768 bytes (32 KiB)** after an ordinary write reply, kills the tracked guest, boots the same stable disk with a fresh backend and runs recovery twice. The protected baseline and actual 5000 us host policy remain unchanged; the guest/host filesystem UUIDs differ. An orderly recovery shutdown leaves zero pending model writes. Exact package, harness and calibration hashes match before publication. This adds one selected between-request cache-loss ordering on the new installer, not every transition.

The current unit suite passes 88 tests, fresh installation integration passes and all 40 process-crash cases pass on the repaired module. The working host's installed helper remains byte-identical, with power/timer active at 5000 us and no pending installation transaction. Root shells are closed after qualification.

## Remaining limits

This qualification covers selected process interruptions followed by orderly unmount/remount and deliberate ownership replacements. It is not physical reboot, volatile-cache loss, torn-write or concurrent administrator mutation qualification. The fresh [40-case process matrix](evidence/stage0-persistent-ownership-process-crashes.json) checks the new journal format separately. Earlier VM and cache-loss reports retain their own source hashes. The fresh selected cache-loss run above qualifies only its recorded repaired payload and boundary; the earlier full VM matrix has not been rerun on this version. Broader interrupted-recovery orderings, separate native benchmark volumes, physical boot/resume/recovery and physical-write measurements remain Stage 0 gates. The subsequent [workspace-provenance qualification](workspace-provenance.md) repairs private OS construction records and documents a static audit of the unchanged worker cache key. This earlier matrix specifically covers installer transactions.
