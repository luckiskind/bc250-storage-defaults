# Stage 0 baseline and recovery record

Status: **in progress**. This record is part of the [active development roadmap](DEVELOPMENT_PLAN.md). Stage 0 is not complete and new accelerator subsystems have not been promoted.

The 12-person staffing model in the roadmap is a planning assumption. Current execution uses one agent and one connected BC-250; no independent hardware fleet has been qualified.

## Pinned reference

- Release: [v0.1.0](https://github.com/luckiskind/bc250-storage-defaults/releases/tag/v0.1.0).
- Reference commit: `c9ee4b2133af11e6ffb85f017c8a197997889df8`.
- Reference source tree: `c88de25a36eea6465514aeffb5f6f3eba62fb1f7`.
- The installed lab deployment originally predates the portable package. Its private configuration/exclusions are retained; it has not been replaced by running the public installer over it.

The complete roadmap is a development objective. Its proposed performance targets are not achieved results.

## Recorded host configuration

| Item | Observed value |
| --- | --- |
| CPU | AMD BC-250, 16 logical CPUs |
| Kernel | `7.2.8-1.219-cachyos-bore-bc250` |
| System RAM reported by the kernel | 15,564,660 KiB |
| Driver-reported graphics memory limits | 512 MiB VRAM/visible VRAM, 12 GiB GTT; these counters are not additional physical RAM |
| SSD/controller | PNY CS2241 1TB SSD, firmware `CS224301`, `nvme0` |
| Link | 5 GT/s, width 2 |
| Root/home filesystem source | `/dev/nvme0n1p2`, Btrfs |
| Mount policy | `noatime,compress=zstd:1,ssd,discard=async,space_cache=v2` |
| Scheduler | kyber |
| Queue defaults | 256 requests, 256 KiB read-ahead, 256 KiB maximum sectors |
| Live NVMe latency tolerance | 5000 microseconds |
| User-namespace isolation | Available; bubblewrap probe passed |
| Kernel virtualization device | `/dev/kvm` absent at capture; kernel configuration alone does not prove availability |
| Filesystem/tracing kernel features | Btrfs, EROFS compression, BPF, ftrace, memory cgroups and user namespaces configured |

Capture with `sudo python3 tools/capture_baseline.py > baseline.json`. The command reads selected system metadata, known installed-file hashes and aggregate ledger counts. It does not change power, layout, service configuration or kernel tracing state. Without root, private sources are marked unavailable rather than treated as verified.

The recorder omits hostnames, controller serials, usernames, process arguments, arbitrary configured roots/exclusions, raw journal entries and file-level ledger paths. A privileged capture after the repaired pass confirmed all seven installed file hashes against the manifest.

## Incident discovered during the first audit

The previous maintenance pass exited at the encoded-extent assertion. Its SHA-256 check had completed successfully before reaching that assertion. A read-only audit found a residual 32 KiB compressed extent in `/usr/lib/libgs.so.10.08`, the likely next candidate after the last recorded successful library. The worker did not record the failing path explicitly, so that identification is an inference rather than a recorded exception field.

The retry timer was stopped temporarily. The NVMe power service remained active at 5000 microseconds.

Three private-copy experiments used the same library bytes:

| Copy / synchronization | Maximum encoded extent after processing | Hash result |
| --- | ---: | --- |
| Byte copy / existing range synchronization | 16 KiB | Match |
| Reflink copy / existing range synchronization | 16 KiB | Match |
| Reflink copy / fsync after each range | 16 KiB | Match |

Those copies did not initially reproduce the failure. A subsequent fresh-installer run inside a private user namespace reproduced a 32 KiB residual extent in the 2 MiB synthetic fixture. Adding a strictly bounded stronger-flush retry corrected it. The installed-worker disposable validation also needed 98,304 retry bytes and then reached the verified target. The exact kernel cause of the larger extent remains unproven.

The fix retains verification. A file that remains above target after the bounded retry receives the explicit status `layout-not-achieved-verified`; it is not counted as successfully repacked. Its unchanged signature is remembered to avoid endless rewriting. Content mismatches still stop maintenance through the STOP marker.

See [Btrfs's advisory extent-target behavior](https://btrfs.readthedocs.io/en/latest/btrfs-filesystem.html) and [the limitations of range synchronization](https://man7.org/linux/man-pages/man2/sync_file_range.2.html). Final fsync and before/after content verification remain part of the operation.

## Qualification completed so far

- [x] Preserve the starting release commit and source-tree identity.
- [x] Capture actual host policy and filesystem devices without exposing unrelated user data.
- [x] Verify the installed files against their private deployment manifest.
- [x] Reproduce a residual encoded-extent problem on disposable data.
- [x] Pass 48 isolated Linux tests, including bounded retry, pre-mutation budget reservations, installer transaction recovery and disposable-OS/image filesystem guards.
- [x] Exercise actual installer file operations inside a disposable bubblewrap root.
- [x] Exercise repeat application/removal and restoration against simulated sysfs/service control.
- [x] Execute the real installed resume hook after a simulated controller reset in that private root.
- [x] Verify administrator-edit refusal and failed-enable cleanup/reinstall in isolation.
- [x] Verify partial file-write failure cleanup and preservation of pre-existing destinations.
- [x] Back up the original installed worker, manifest and a consistent SQLite ledger before repair.
- [x] Apply the tested worker repair and verify a normal bounded production maintenance pass.
- [x] Restore the previously enabled timer and confirm the 5000 us drive policy.
- [x] Journal installation/removal and expose explicit recovery with strict file-ownership checks.
- [x] Pass 40 real SIGKILL recovery checkpoints in a disposable Btrfs namespace.
- [x] Build native B0/B1/B2 data copies, verify all 15 hashes and absence of shared extents, and record distinct layout histograms.
- [x] Prepare an authenticated independent Arch userspace with recorded guest package inventory.
- [x] Pass 11 lifecycle checks using real guest systemd, including bounded maintenance, undo/reinstall and startup policy reapplication after a guest reboot.
- [x] Boot a separate stock kernel and Btrfs image, verify orderly persistence, and reset to a protected baseline using fresh overlays.

The repaired pass processed 104 verified files, with 536,367,504 logical bytes processed and 425,984 extra retry bytes. Total charged work was 536,793,488 bytes, within the 536,870,912-byte pass budget. The successful pass took approximately 34.8 seconds including scanning and the quiet check. This timing is an operational observation, not a controlled throughput comparison.

The post-pass ledger held 482 recorded successfully repacked file signatures. That count describes recorded results, not a fresh audit of the current content of every program file. The new attempts ledger recorded 104 completed repacking attempts and no unfinished reservations at capture.

## Isolation boundary and remaining gaps

`tests/integration_install.py` runs as an ordinary user using a disposable Btrfs directory as its root. It mounts required host executables/libraries read-only, supplies private config/state/hooks/sysfs, replaces systemctl inside the namespace, hides host runtime sockets and unshares the network. `tests/crash_install.py` uses the same boundary to kill the real installer and then invoke explicit recovery. It must not be described as a real boot or real controller-power test. See [the recorded interruption matrix](evidence/stage0-installer-crash-tests.json) and [recovery invariants](recovery.md).

`tools/build_baseline_datasets.py` created independent byte copies of four ELF libraries and a 32 MiB incompressible control, with zero shared extents. [The manifest](evidence/stage0-native-baseline-manifest.json) records native B0/B1 layouts and verified 16 KiB compressed extents in all four B2 ELF copies. B0/B1/B2 controller values in that manifest are intended measurement policies; the builder never applies them. Power comparisons should reuse the same immutable native files across controller settings so incidental allocation differences cannot masquerade as a power-policy effect. These are preparation results, not performance measurements or independently bootable OS images.

Pending before declaring Stage 0 complete:

- [ ] Qualify storage-profile installation/recovery under whole-guest interruption in the separately bootable test OS. Userspace service tests and separate-kernel image boot/reset now pass; the combined fault cases remain open.
- [ ] Test actual boot/reboot and suspend/resume transitions with measured controller state.
- [ ] Test device/storage power-loss recovery, including interrupted recovery itself, across installer and worker transitions on disposable storage. Process SIGKILL testing is complete for 40 selected installer checkpoints only.
- [ ] Recreate independent full-system/volume B0/B1/B2 baselines; the native data-copy preparation above covers only the dataset part of this gate.
- [ ] Establish a boot/recovery path applicable to the physical BC-250. The virtual kernel/image reset path is qualified; physical firmware/bootloader and hardware recovery remain open.
- [ ] Quantify physical write amplification, metadata growth and lost sharing; logical work budgets are not physical-write limits.

No host reboot, suspend, kernel replacement, filesystem formatting or destructive fault injection was performed in this initial milestone. The working installation is not the power-loss-test target.

Later virtual-lab formatting in this record is restricted to new regular image files. No host device was formatted.

## Real-systemd userspace qualification

The [reusable harness result](evidence/stage0-real-systemd-result.json) records 11 passing lifecycle checks in a freshly prepared Arch tree: Python 3.14.8, systemd 262.1, real guest PID 1, real Btrfs and real installer/service operations. The controller files are simulated and attached only inside the guest. Qualification uses private networking and an isolated user range, with 1 GiB memory and a two-CPU quota. The copied ELF worker fixture verified 6,344,456 bytes and charged 6,442,760 bytes including a 98,304-byte bounded retry, below the 16 MiB test budget. Startup after a guest reboot reapplied the policy to a freshly reset simulated controller, and undo restored 100000 us in that fixture. The host retained its active services and actual 5000 us policy.

Two environment limitations were resolved before this pass: nspawn's late API-filesystem setup hid early custom sysfs mounts, so the fixture is attached by an early guest service with a marker guard; Btrfs defrag refused ID-mapped ownership, so the dedicated guest tree uses shifted physical IDs while retaining user-namespace isolation. Failed exploratory runs were preserved privately. The public evidence comes from a fresh tree using the reusable tool and unchanged production installer/helpers.

See [the qualification guide](real-systemd-qualification.md) for commands, scope and primary-source references. This is an independent userspace, not an independent kernel or storage volume. No performance comparison, physical controller reset or device power-loss result is inferred from it.

## Separate-kernel virtual recovery qualification

The [virtual recovery result](evidence/stage0-virtual-recovery-result.json) records three passing boots using QEMU 11.1.2 and stock Linux `7.2.11-arch1-1`, with real guest systemd and a separately formatted 80 GiB sparse Btrfs image. A committed state record and reference fixture survived an orderly restart. A fresh qcow2 overlay reset the guest to the protected baseline without its prior state. The baseline sparse fingerprint stayed unchanged, and the host wrapper verified that the guest filesystem UUID differs from the workspace filesystem's UUID. The recorded source hashes match the executed tools.

The wrapper uses an isolated user range, private networking, no guest NIC, two CPU equivalents, a 2 GiB memory ceiling and a 768 MiB VM. The working power/timer services remained active at 5000 microseconds. CPU emulation and layered image I/O make these correctness results unsuitable as performance evidence. The VM image omits source security xattrs and is a fresh test OS, not a backup of the user's working system.

Failed prototype console runs and a first reusable run whose final host-UUID comparison was attempted inside the sandbox were retained. Reserving the serial console for probe output and moving the read-only host identity comparison to the host wrapper resolved those environment/verifier issues. The public result comes from the corrected wrapper on fresh overlays against a newly built artifact set.

See [the virtual image/boot recipe](virtual-recovery.md). This qualifies orderly recovery/reset of the virtual reference. It does not qualify interrupted installation across whole-guest failure, physical SSD cache loss, physical suspend/resume, or independent B0/B1/B2 benchmark volumes.

## Recovery procedure for the local reliability repair

The repair saved root-only backups under `/var/lib/bc250-storage-defaults/reliability-backups/`, including the original worker, original manifest and a consistent ledger copy. Inspect the selected backup and verify its hashes before any intentional restoration.

If maintenance fails again:

1. Stop `bc250-btrfs-repack.timer`; leave the independent power service alone unless its own behavior is under investigation.
2. Preserve the journal, manifest, last-run report and ledger before resetting failure state.
3. Check whether content verification failed, layout verification missed its target, or the process was interrupted. Do not delete a STOP marker merely to force another run.
4. Reproduce on a private copy and verify a repair before replacing the owned helper.
5. Restore only the intended verified helper/manifest if rollback is needed. Restoring an old ledger would erase accounting/history and requires separate justification; keeping a backup is not authorization to rewind it.
6. Restart the worker once under its normal budget, inspect the result, then restore the timer.

Undoing the package stops future maintenance and restores the captured power setting. It does not reconstruct previous compressed extents or snapshot/reflink sharing. Existing backups are not a substitute for a qualified full-system recovery environment.
