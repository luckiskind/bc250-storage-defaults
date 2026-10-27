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
- [x] Pass 88 isolated Linux tests, including bounded retry, pre-mutation budget reservations, installer transaction recovery and disposable-OS/image filesystem guards.
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
- [x] Pass seven selected installer recovery scenarios across eight acknowledged whole-guest interruptions and 15 guest boots, including interrupted recovery and missing-link compatibility repair.
- [x] Independently calibrate a volatile disk-cache model and recover one installer VM after discarding 100 KiB of actual pending model writes.
- [x] Pass a real-worker baseline and three cache-loss recovery boundaries across seven VM boots, preserving hashes and conservative reservations.
- [x] Apply tested ledger commit hardening to the owned host helper with configuration/history preserved and all seven installed hashes verified.

The repaired pass processed 104 verified files, with 536,367,504 logical bytes processed and 425,984 extra retry bytes. Total charged work was 536,793,488 bytes, within the 536,870,912-byte pass budget. The successful pass took approximately 34.8 seconds including scanning and the quiet check. This timing is an operational observation, not a controlled throughput comparison.

The post-pass ledger held 482 recorded successfully repacked file signatures. That count describes recorded results, not a fresh audit of the current content of every program file. The new attempts ledger recorded 104 completed repacking attempts and no unfinished reservations at capture.

## Isolation boundary and remaining gaps

`tests/integration_install.py` runs as an ordinary user using a disposable Btrfs directory as its root. It mounts required host executables/libraries read-only, supplies private config/state/hooks/sysfs, replaces systemctl inside the namespace, hides host runtime sockets and unshares the network. `tests/crash_install.py` uses the same boundary to kill the real installer and then invoke explicit recovery. It must not be described as a real boot or real controller-power test. See [the recorded interruption matrix](evidence/stage0-installer-crash-tests.json) and [recovery invariants](recovery.md).

`tools/build_baseline_datasets.py` created independent byte copies of four ELF libraries and a 32 MiB incompressible control, with zero shared extents. [The manifest](evidence/stage0-native-baseline-manifest.json) records native B0/B1 layouts and verified 16 KiB compressed extents in all four B2 ELF copies. B0/B1/B2 controller values in that manifest are intended measurement policies; the builder never applies them. Power comparisons should reuse the same immutable native files across controller settings so incidental allocation differences cannot masquerade as a power-policy effect. These are preparation results, not performance measurements or independently bootable OS images.

Pending before declaring Stage 0 complete:

- [ ] Test actual boot/reboot and suspend/resume transitions with measured controller state.
- [ ] Extend calibrated device-cache fault coverage to additional installer, worker and interrupted-recovery orderings, then qualify physical storage power-loss behavior. One installer boundary and three worker boundaries now pass positive write-loss cases; process SIGKILL coverage remains 40 selected installer checkpoints.
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

See [the virtual image/boot recipe](virtual-recovery.md). This qualifies orderly recovery/reset of the virtual reference. That boot-only probe does not qualify interrupted installation. The subsequent profile fault suite below covers selected installer transitions; physical SSD cache loss, physical suspend/resume and independent B0/B1/B2 benchmark volumes remain open.

## Installer durability across whole-guest interruption

The [seven-case profile fault result](evidence/stage0-virtual-profile-faults.json) records eight acknowledged QEMU SIGKILLs and 15 boots against a new protected Btrfs baseline. It covers partial staging, power/timer activation, committed installation, interrupted removal and an interrupted recovery. Every final recovery is repeated, followed by checks of owned payloads, pending/staged artifacts, services and simulated power restoration. A deliberate missing-timer-link compatibility case is recorded separately from naturally occurring interruption. The fixed install's ordinary committed case verifies enabled/active startup **before** recovery, then verifies preservation and normal undo.

This work found a real installer failure in the prior development version: a committed active manifest survived while the newly created timer dependency directory did not. An isolated child overlay confirmed the missing directory. The repair synchronizes service-link directories and their parent before committing activation or completed shutdown. Committed recovery audits installed contents and remaining staging artifacts, then reestablishes the intended enabled services before finishing cleanup. Failed and diagnostic images were preserved. The repaired source passes 55 isolated tests and a [fresh 40-case process interruption rerun](evidence/stage0-service-link-process-crashes.json).

The final VM result verifies unchanged protected-baseline bytes, a separate guest filesystem identity, matching package/build/runtime source hashes and unchanged actual host policy at 5000 us. The working power service and timer remained active. The host was not rebooted. The [reproduction guide](virtual-profile-faults.md) distinguishes guest-memory loss from physical volatile-cache loss. Interrupted worker repacking and device-level failure models remain open; no new throughput comparison was performed.

## Calibrated device-cache loss

The [independent calibration report](evidence/stage0-cache-calibration.json) passes four QEMU-client scenarios: acknowledged unflushed write loss with an armed cut, flush survival, FUA isolation/overlap handling, and actual backend process SIGKILL followed by readback through fresh processes. The disk keeps ordinary writes only in bounded RAM; FLUSH and FUA synchronize their specified durable state before successful replies. Its source hashes and the caller's harness hashes identify the executed versions.

The [cache-backed installer VM result](evidence/stage0-cache-installer-vm.json) then passes recovery after **102,400 bytes (100 KiB)** of pending disk-model writes were discarded. The installer paused after power/timer activation; the disk cut after its next ordinary write reply; the tracked guest was killed and rebooted on the same stable raw file with a fresh backend. Recovery twice verified the disposable fixture, removed the uncommitted installation/staging/journal, disabled services and restored the simulated original policy. Orderly shutdown left zero pending backend bytes. The protected baseline, separate guest filesystem identity, matching calibration/package/runtime source hashes and actual host 5000 us policy all verified. The suite now passes 73 unit tests.

An earlier immediate guest-kill run recovered but discarded zero backend-cache bytes; it is not counted as device-cache-loss evidence. A preboot metadata-mode mismatch was also preserved and corrected with a regression test. Accepted evidence comes from the calibrated request-triggered cut. See [the procedure and limits](volatile-cache-faults.md).

This is one selected installer boundary with a calibrated software device model. It does not qualify interrupted worker repacking, all installer transitions, torn writes, partial barriers, physical SSD cache/firmware/NAND behavior, physical reboot/resume, or native throughput. Earlier profile reports retain their own tested source versions; this addition changes the lab harness and leaves installed payloads unchanged.

## Worker reservations and live ledger hardening

The [worker cache-loss matrix](evidence/stage0-worker-cache-vm.json) passes a baseline and three fault scenarios across seven guest boots. The full 6,344,456-byte ELF fixture retains its expected hash and reaches 16 KiB encoded extents. Cuts after the committed reservation, after eight real range-sync operations, and after verification/before final charging discard 49,152, 110,592 and 49,152 pending model bytes respectively. Each original 7,393,032-byte uncertain reservation survives exactly. Recovery preserves that charge, safely completes or recognizes the verified layout, and a repeated pass changes neither attempts nor budget. SQLite integrity and file metadata verify; the actual worker uses live virtual-root disk counters through a documented test-only pathname adapter.

The worker now explicitly establishes and reads back SQLite synchronous=EXTRA, accepts DELETE/WAL journal modes, and synchronizes the state directory's parent before reservations can authorize layout changes. This hardens a documented SQLite durability-contract gap; the selected tests did not demonstrate a lost reservation in the former version. See [SQLite's contract](https://www.sqlite.org/pragma.html#pragma_synchronous) and [the worker qualification guide](worker-cache-recovery.md). The expanded suite passes 79 isolated Linux tests; the [fresh 40-case installation process-crash rerun](evidence/stage0-worker-ledger-process-crashes.json) also passes with the new payload.

The [live repair record](evidence/stage0-worker-ledger-live.json) verifies helper SHA-256 `010eace2c9de50f8a4f94961073661b9f6ab2d2412cdeca0416795df7185a8f0`, all seven installed file hashes, unchanged configuration and preserved old charges, a consistent root-private ledger backup, actual DELETE/EXTRA policy and a successful disposable content/layout check. A normal service pass succeeds with zero additional processing because 643,253 bytes remain in its UTC-day allowance, below the 1 MiB minimum file size. That limit was respected, not reset. The power service and timer remain active at 5000 us.

These are selected software crash/accounting results, not physical SSD power-loss or throughput results. The deployed ledger schema and history remain intact. Broader recovery interleavings and the remaining Stage 0 volume/hardware/write-amplification gates are still open.

## Persistent installer ownership across mount changes

The [native reproduction](evidence/stage0-mount-identity-reproduction.json) changes an unchanged Btrfs image's device number from 136 to 138 while preserving UUID, inode and content. The former installer then refuses staging/removal recovery, preserving files and journals. New version 2 journals record full Btrfs UUID plus opaque Linux export handle, and the descriptor used for identity also supplies the content hash. Existing version 1 journals retain their original strict checks; no content-only migration is permitted.

The [seven-case native matrix](evidence/stage0-persistent-ownership.json) passes after real device-number changes and actual installer SIGKILL. Published rollback, committed cleanup and interrupted removal complete idempotently. Identical replacement of both hardlink names, a same-inode/content snapshot, and two legacy-device-mismatch cases are refused with zero service calls and all present files/witnesses/journal bytes unchanged. Two new regular sparse image files are the only formatted targets; all test mounts are removed and images retained. Services/controller operations are simulated. See [the procedure and exact limits](persistent-ownership.md).

The current 88 isolated Linux tests, fresh installation integration and [40-case process interruption rerun](evidence/stage0-persistent-ownership-process-crashes.json) pass. The rebuilt [selected installer cache-loss VM case](evidence/stage0-persistent-ownership-cache-vm.json) also passes with matching package/calibration hashes after dropping 32 KiB, killing the guest and recovering twice; its baseline is unchanged and recovery leaves zero pending model writes. Installed helper bytes remain unchanged; the actual timer and power service remain active at 5000 us with no pending host installation transaction. This installer-only change does not alter repacking policy or claim a new throughput gain. Broader fault/recovery orderings, private-lab/worker boot-dependent identity review, independent native volumes, physical boot/resume/recovery and physical-write measurements remain open.

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
