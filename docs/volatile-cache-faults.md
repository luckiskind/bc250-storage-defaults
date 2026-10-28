# Calibrated volatile disk-cache failure lab

This development tool models a failure the earlier VM SIGKILL tests did not: loss of writes acknowledged by a virtual disk but still held in its volatile cache. It uses only newly created regular test files inside the private lab. The working BC-250 stays powered and its actual drive is never exported to the VM.

## Model and independent calibration

`tools/volatile_disk.py` exposes a restricted fixed-newstyle NBD export over a private Unix socket. Ordinary aligned writes go exclusively to a bounded RAM sector map. Reads combine that map with the stable regular file. FLUSH writes the pending sectors, synchronizes the file and only then replies. FUA synchronizes its own write and removes older cached versions of the same sectors, while unrelated pending sectors remain volatile. These boundaries follow the [NBD ordering contract](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md#ordering-of-messages-and-writes).

The model can discard RAM explicitly or arm a cut after the next ordinary write reply. Arming does not discard completed FUA writes. It also does not turn a FLUSH into a failure. An actual backing-file I/O error invalidates the test instead of being treated as a simulated successful persistence event. Cache exhaustion returns an explicit error without partially modifying the pending map; VM qualification rejects any such exhaustion.

The supported client path uses READ, WRITE, FLUSH and FUA with simple replies, one connection at a time and 512-byte alignment. It advertises no trim, write-zeroes, structured replies or multi-connection cache coherence. It is a correctness fixture for the lab's QEMU client, not a production block server or a claim of complete NBD implementation coverage.

Before testing filesystem recovery, `tools/calibrate_volatile_disk.py` drives the actual server with QEMU's separate `qemu-io` client. It verifies the expected bytes again through a fresh server and fresh QEMU client after every cut. These checks do not substitute a mock client for the protocol implementation.

| Calibration | Expected evidence |
| --- | --- |
| Unflushed loss and armed cut | A write is acknowledged and read back, then an armed ordinary write causes cache loss. Both ranges revert to their original bytes on restart. The triggering command may race delivery of its own reply; the earlier acknowledged write is the durability negative control. |
| Flush survival | Flushed data survives while a later ordinary write disappears. |
| FUA isolation and overlaps | FUA data survives; older overlapping cache entries cannot resurrect it; unrelated cached sectors and a later ordinary overwrite disappear. |
| Actual backend SIGKILL | Killing the server process loses its pending RAM writes, while prior FLUSH and FUA data survive a fresh process and client. No final server report is fabricated for SIGKILL. |

The calibration uses a fresh 32 MiB regular file and a 4 MiB cache. Unit tests additionally cover capacity refusal, bounds/alignment, short writes, stable-file/fsync failure reporting, ownership, private paths, symlink/hardlink refusal, exclusive locking and raw protocol acknowledgements. The VM disk uses a 64 MiB cache under the existing 2 GiB parent memory ceiling, without swap allowance.

## Reproduce

First prepare the dedicated signed-package toolchain in [the virtual-lab guide](virtual-recovery.md). Use a new calibration artifact label; previous results are preserved.

```sh
sudo python3 tools/virtual_test_lab.py cache-calibrate \
  --workspace /path/to/vm-test --artifact-label cache-v1 --run-label calibration-01
```

The host wrapper saves `vm-cache-calibration-cache-v1-calibration-01.json` in that private workspace. It records the executed model/client hashes, QEMU version and unchanged actual host policy. Inspection uses private report files and escaped console logs. Public evidence contains selected metadata, not disk images or full logs.

Build a profile image from the unchanged package and guest-builder source as described in [the installer VM fault guide](virtual-profile-faults.md), then run:

```sh
sudo python3 tools/virtual_test_lab.py cache-profile-test \
  --workspace /path/to/vm-test --artifact-label profile-v1 --run-label cache-fault-01 \
  --calibration-report /path/to/vm-test/vm-cache-calibration-cache-v1-calibration-01.json
```

The wrapper requires a complete passing calibration and matching model/client source hashes. The report must be an owned regular file inside the private toolchain workspace and cannot be writable by other users. Embedded package/build hashes must also match. Changing the disk model requires recalibration; changing the package or embedded guest builder requires a new profile image.

The runner creates a fresh, ordinary sparse byte copy of the protected raw baseline with reflinks disabled. It compares canonical logical digests before boot: virtual size plus each nonzero 4 KiB block's offset, length and bytes. This deliberately ignores differences in allocation of zero-filled ranges and is not a full-image SHA-256. The original baseline's separate sparse-layout fingerprint must remain unchanged after the test.

The actual installer pauses after its power service and timer have been enabled, before installation commit. The host then arms the modeled disk to cut after its next ordinary write reply. The guest kernel may continue background writeback while the installer is paused. Once the disk report proves a positive number of discarded cached bytes, the runner kills only its tracked QEMU process and boots the same stable file with a fresh backend. It runs recovery twice and checks the original fixture, installed/staged paths, journal state, service removal and simulated power restoration. An orderly recovery shutdown must leave no pending backend writes.

This selected scenario is not automatically promoted to every installer or worker transition. In particular, a recovery pass with zero discarded cache bytes does **not** establish device-cache-loss coverage. An initial immediate guest-kill attempt produced exactly that zero-byte result and was retained as exploratory evidence rather than counted as a cache-loss qualification. A separate preboot attempt stopped on an overly strict metadata-permission check; the corrected check retains protection against other writers.

## Recorded evidence

The [four-case calibration](evidence/stage0-cache-calibration.json) passes with QEMU 11.1.2 and the recorded exact source hashes. The [selected installer VM case](evidence/stage0-cache-installer-vm.json) passes after discarding **102,400 bytes (100 KiB)** of pending model data. Recovery is repeated, the same guest filesystem mounts successfully, and its orderly shutdown leaves zero pending writes. The calibration file's unchanged public bytes match the VM report's prerequisite SHA-256. The protected baseline and actual host policy remain unchanged. The expanded isolated Linux suite passes 73 tests.

The later [persistent installer ownership repair](persistent-ownership.md) has its own rebuilt [selected cache-loss result](evidence/stage0-persistent-ownership-cache-vm.json). That repaired payload recovers twice after 32 KiB of positive model write loss, with unchanged prerequisite calibration bytes, baseline and host policy. The original 100 KiB result above remains evidence for its pinned earlier payload; differing lost-byte counts reflect selected pending writes, not a performance comparison.

## Limits and next qualification

Cuts occur between backend requests. In-progress FLUSH/FUA operations finish before the cut lock; partial barriers, torn sectors, arbitrary reordering, controller firmware failures and NAND behavior are not modeled. The host kernel, its filesystem and the actual SSD remain powered. Real hardware can persist ordinary writes earlier than this deterministic model does.

These are software durability/correctness results. They measure neither native throughput nor physical power-loss behavior. Source hashes identify the exact executed components in each report; older qualification reports retain their own source versions rather than implying that every historical harness hash equals the latest branch.

The subsequent [worker recovery matrix](worker-cache-recovery.md) now covers three actual repacker boundaries, content integrity and conservative budget reservations. Next work includes more installer/worker/interrupted-recovery orderings. Independent native benchmark volumes, physical boot/resume/recovery and physical-write/metadata/sharing measurements remain separate Stage 0 gates.
