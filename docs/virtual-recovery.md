# Separate-kernel virtual recovery lab

Development branch only. This adds a recoverable test target for kernel/filesystem work while preserving the working BC-250 installation. It is a correctness environment, not a throughput benchmark or a replacement for physical boot/resume and power-loss qualification.

## What is isolated

QEMU boots a stock distribution kernel and a file-backed Btrfs root volume. The tested software CPU emulator was QEMU 11.1.2; the guest kernel was `7.2.11-arch1-1`, distinct from the working BC-250 kernel. Hardware virtualization was not exposed on the connected machine. QEMU runs inside a dedicated user namespace with private networking, no guest NIC, no host filesystem passthrough and only regular image files as guest disks. Its parent scope allows at most two CPUs and 2 GiB memory, with a 1536 MiB memory-high threshold and no swap allowance. Each VM has 768 MiB RAM. The wrapper requires 6 GiB available host memory and the userspace builder's 72 GiB host free-space floor.

The image is an 80 GiB sparse regular file. That is virtual capacity, not an 80 GiB allocation or reservation. Btrfs is formatted only in a newly created regular file; the helper never passes a host block device to the formatter. The recipe uses [Btrfs's file-backed root-directory population](https://btrfs.readthedocs.io/en/latest/mkfs.btrfs.html), zstd:1, single data and duplicated metadata. The test root is a fresh distribution copy, excluding runtime directories and security xattrs from the mapped preparation environment. It is not a backup of the user's OS and does not qualify preservation of those omitted xattrs.

A protected raw baseline is opened read-only as the backing file for disposable qcow2 overlays. See [QEMU's image model](https://www.qemu.org/docs/master/system/images.html). This deliberate shared backing is appropriate for reset/recovery checks. It does **not** establish independent B0/B1/B2 benchmark volumes or preserve a historical pre-study user installation.

## Build and run

Start with a NEW dedicated workspace prepared as described in [the userspace qualification guide](real-systemd-qualification.md). Reuse the authenticated/pinned Arch seed, not the userspace tree that already passed the real-systemd service test.

```sh
sudo python3 tools/prepare_test_os.py extract \
  --workspace /path/to/new/vm-test \
  --archive /path/to/archlinux-bootstrap-2026.10.01-x86_64.tar.zst
sudo python3 tools/prepare_test_os.py install-deps --workspace /path/to/new/vm-test

sudo python3 tools/virtual_test_lab.py packages --workspace /path/to/new/vm-test
sudo python3 tools/virtual_test_lab.py build \
  --workspace /path/to/new/vm-test --artifact-label baseline-v1
sudo python3 tools/virtual_test_lab.py boot \
  --workspace /path/to/new/vm-test --artifact-label baseline-v1 --run-label correctness-01
```

Package preparation performs a signed distribution update inside that dedicated userspace and installs QEMU, the stock kernel and initramfs tools. It changes no host package database or boot files. The toolchain inventory records exact package versions; the seed pin alone does not pin the final rolling distribution. Once image construction starts, the wrapper refuses package preparation in that tree. `inventory` may be used to record an already prepared toolchain without updating it.

The builder makes ordinary copies of the test OS files, creates a generic initramfs containing the virtual block drivers, then formats the new image. [Direct Linux boot](https://www.qemu.org/docs/master/system/linuxboot.html) keeps the known kernel/initramfs outside the guest root disk. Their hashes are checked before every boot. This verifies an explicit kernel/image recovery path; it does not test a physical bootloader, firmware or secure-boot chain.

Each artifact set has a separate private directory under `artifacts/`. Each boot run creates a new directory beneath that set's `runs/`. Existing overlays/run directories are refused, not overwritten. A workspace lock prevents overlapping wrapper actions. The staged helpers refuse symlinks, special nodes and hardlinks before truncation. Failed images/logs are retained for inspection.

## Passing evidence

The three-boot sequence checks:

1. A fresh overlay boots real guest systemd with Btrfs as `/`, verifies the reference ELF fixture and atomically saves/fsyncs a state record.
2. A second boot of the same overlay verifies that record, its nonce and the fixture bytes, while confirming a new kernel boot ID.
3. A new overlay against the original baseline boots without the prior state, demonstrating reset to the protected reference.

The host wrapper verifies that the guest Btrfs UUID differs from the workspace filesystem's UUID. The protected raw baseline's sparse fingerprint must remain unchanged. This fingerprint hashes virtual size, data-range offsets/lengths and logical bytes in non-hole ranges; it is explicitly **not** a SHA-256 of all logical bytes in the 80 GiB image or a measure of compressed physical allocation.

The wrapper saves `vm-recovery-<artifact-label>-<run-label>.json` in the private workspace, including guest results, boot-artifact hashes, source hashes, scope flags and the actual host-policy check. Review reports before redistribution. The working host's actual latency-tolerance value must remain 5000 microseconds. This boot-only sequence leaves the storage profile uninstalled. The separate [profile fault suite](virtual-profile-faults.md) embeds the actual package and qualifies selected installation/removal/recovery transitions across abrupt guest loss.

Orderly persistence and clean overlay reset do not establish interrupted-operation correctness or device-cache power-loss durability. `cache=writeback` is recorded in the QEMU invocation; no volatile-device-cache loss model is inferred from it. A host-side QEMU kill would lose guest RAM but does not by itself reproduce all physical SSD failure modes. Raw images, qcow2 files and console logs remain private lab artifacts; the repository stores code and selected result metadata.

## Failed-run diagnostics

An initial prototype reached the guest login console but its probe exited with status 120 while sharing that console with serial-getty. Both that run and a bounded diagnostic overlay were preserved. Reserving ttyS0 for probe output by masking only the guest's serial-getty instance resolved the test-output failure. Subsequent ordinary multi-user boots passed; the fix did not bypass systemd startup or the filesystem checks.

To inspect a failure, use a new run label:

```sh
sudo python3 tools/virtual_test_lab.py diagnostic \
  --workspace /path/to/new/vm-test --artifact-label baseline-v1 --run-label diagnosis-01
```

This enables guest systemd console diagnostics and has a bounded deadline. A diagnostic command's zero exit status is not a passing three-boot qualification; inspect the result/report scope. Serial logs contain terminal-control sequences. Inspect them through escaped text or a text viewer rather than printing them raw into an interactive root terminal.

A first reusable run passed all three guest boots but its final verifier could not resolve the host filesystem UUID from the sandbox's restricted device view. The corrected wrapper reads that identity on the host and compares it with the guest reports. This keeps the device isolation intact. The retained failed run is not counted as a passing full qualification.
