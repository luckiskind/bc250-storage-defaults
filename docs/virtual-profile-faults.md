# Storage-profile recovery across abrupt guest loss

Development qualification only. This extends the [separate-kernel virtual lab](virtual-recovery.md) with the actual installer, installation journal, shipped helpers and real guest systemd. The controller's identity and power files are explicitly simulated inside the VM. The working host controller is never attached to it.

## Reproduce

Use the dedicated, signed-package VM toolchain prepared in the virtual-lab guide. Build a **new** artifact label; this leaves prior baselines intact.

```sh
sudo python3 tools/virtual_test_lab.py profile-build \
  --workspace /path/to/vm-test --artifact-label profile-v1
sudo python3 tools/virtual_test_lab.py profile-test \
  --workspace /path/to/vm-test --artifact-label profile-v1 --run-label faults-01
```

The image embeds copies of the nine required package files and their SHA-256 hashes. The guest verifies them and the reference fixture before every operation. No host directory is passed through to the VM. An early guest service loads the NVMe driver, refuses any actual controller in its otherwise empty NVMe class, attaches the marked fixture and resets its initial value to 100000 us before the profile power service starts. These simulated values do not measure physical NVMe behavior.

Build and run from the same unchanged source checkout. The wrapper rejects changes to the package, image builder or embedded guest program between construction and qualification; rebuild under a new artifact label when those sources change. Kernel/initramfs hashes are checked before each boot.

The runner creates a separate qcow2 overlay for each case. The guest imports the real installer and instruments only selected function boundaries to announce a checkpoint on its serial console. The announcement carries a fresh per-boot token. It writes no checkpoint marker and requests no sync or orderly shutdown. The runner validates the acknowledgement and sends SIGKILL to the exact QEMU PID it launched. It then boots the **same overlay**, runs explicit recovery twice and checks the result. Unknown, stale or duplicate results cannot silently count as a pass.

| Case | Interruption | Required recovery result |
| --- | --- | --- |
| `partial-stage` | Half of the first staged payload written, without an added fsync | Uncommitted installation removed |
| `power-enabled` | Real power service enabled and started | Installation removed; original simulated value restored |
| `timer-enabled` | Real power service and timer enabled and started | Installation removed; both disabled |
| `manifest-committed` | Installation manifest atomically committed and synchronized | Committed installation preserved, owned hashes checked and services active; normal undo then succeeds |
| `legacy-missing-timer-link` | Explicitly remove and synchronize the committed timer startup link, then interrupt | Recovery repairs that link and activates the committed profile; normal undo succeeds |
| `removal-started` | Normal installation followed by the first synchronized payload deletion during removal | Removal completes |
| `recovery-interrupted` | Installation cut after timer activation; recovery cut after its first payload deletion | A third boot completes recovery |

All recovery boots check the real systemd PID 1, Btrfs root, distinct pinned guest kernel, reference content, no pending transaction or staged payload names, final absence of installed payloads, disabled services and restored simulated value. The committed-install case additionally checks its preserved active state before undo. The host wrapper verifies that the guest filesystem identity differs from the workspace's identity and that the host's actual drive policy remains 5000 us. The protected baseline's sparse fingerprint must be unchanged.

The ordinary committed-manifest case checks enabled/active services and the 5000 us simulated value **before invoking recovery**, so recovery cannot hide a persistence failure in the fixed installer. The legacy-link case instead verifies the missing/disabled timer link before recovery and checks that explicit recovery repairs it. That case is deliberate compatibility injection, not a claim that the fixed installer naturally lost its link.

Individual cases can be selected with `--cases timer-enabled manifest-committed`. Each boot has a 300-second deadline, bounded console output and private logs. Failed disks and logs remain preserved; use a new run label. Inspect serial logs as escaped text because guest systemd emits terminal control sequences. The reader removes recognized terminal sequences before parsing its own result marker while still rejecting arbitrary text prefixes and incorrect tokens.

## Evidence and limits

The [recorded qualification](evidence/stage0-virtual-profile-faults.json) passes all seven scenarios, with eight acknowledged QEMU kills and 15 guest boots on the repaired source. The protected baseline and actual host policy remained unchanged. The package/build/runtime hashes match the published source; 55 unit tests and the 40-case process interruption rerun also pass.

Qualification results are saved as `vm-profile-<artifact-label>-<run-label>.json` in the private toolchain workspace. The report records each acknowledged interruption, subsequent recovery, executed source hashes, package and boot-artifact hashes, baseline fingerprint and host-policy checks. Review metadata before publishing it. Images and full console logs remain private.

This models abrupt loss of the **guest RAM and kernel**. The host kernel, host write cache and physical SSD remain powered. It does not model volatile SSD cache loss, torn sectors, arbitrary instruction boundaries, physical BC-250 boot/resume, interrupted repacking or native throughput. It does not qualify qcow2 as a production storage format. Successful selected checkpoints are a bounded recovery claim, not proof against every possible crash.

The next device-failure model must distinguish acknowledged volatile writes from durable writes. Its calibration must demonstrate that ordinary unflushed writes can disappear, completed flushes survive, and completed FUA writes survive without treating unrelated writes as necessarily durable. The [NBD protocol's ordering requirements](https://github.com/NetworkBlockDevice/nbd/blob/master/doc/proto.md#ordering-of-messages-and-writes) provide a concrete interface contract. That model must pass independent calibration before any installer result from it is accepted; it is not implemented by this SIGKILL suite.

The first exploratory run's guest recovered successfully, but its host reader missed a result preceded by systemd terminal queries and rejected the run. That retained run is not a passing qualification. The reader correction is covered by a regression test; accepted evidence must come from a fresh run using that correction.

A subsequent run exposed an installer durability failure: after the active manifest had committed, reboot preserved the power startup link but lost the newly created `timers.target.wants` directory. A child overlay inspected through an isolated guest shell confirmed the absent directory and intact active manifest. The failed parent image was preserved. The installer now synchronizes both dependency directories and their parent before committing activation or recording completed shutdown. Recovery of an interrupted committed install audits owned payloads and remaining staging artifacts, then reestablishes enabled services before finishing cleanup. See the [directory durability requirement](https://man7.org/linux/man-pages/man2/fsync.2.html). These changes affect installation/recovery correctness; they establish no additional throughput gain.
