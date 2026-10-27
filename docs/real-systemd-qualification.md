# Real-systemd qualification in a disposable OS tree

Development branch only; the original v0.1.0 release does not contain these qualification tools.

This test uses its own Arch Linux userspace, real systemd as guest PID 1, real installer file operations and real Btrfs ioctls. It supplies simulated NVMe control files. The host kernel and Btrfs volume are shared. It does not establish physical reboot/resume, separate-volume recovery, kernel-fault containment or device power-loss durability. Do not use this container for kernel crash injection or performance comparisons.

The working BC-250 power policy must already be 5000 microseconds. The harness checks that value before and after the test. It does not install over the host's profile. Failed guest workspaces are preserved; the reusable harness requires a fresh prepared OS for each run.

## Requirements and preparation

Use a source checkout on the BC-250. Host requirements: root access, Python 3.14+ for zstd tar reading, GNU tar, zstd, systemd-nspawn, user namespaces, Btrfs and at least 72 GiB available. The validation tools are separate from the package's Python 3.10+ runtime requirement.

Obtain `archlinux-bootstrap-2026.10.01-x86_64.tar.zst` from the [official mirror](https://fastly.mirror.pkgbuild.com/iso/2026.10.01/). Verify it using [Arch's download-verification procedure](https://archlinux.org/download/), its [signature](https://archlinux.org/iso/2026.10.01/archlinux-bootstrap-2026.10.01-x86_64.tar.zst.sig) and [published checksum](https://archlinux.org/iso/2026.10.01/sha256sums.txt). The builder independently requires this exact SHA-256:

```text
0c9c97b7a58a8a023c9e07f84cb307a9e8006e65d8fc4c17b83ddc8010b45c10
```

The initial lab seed also passed signature verification against the distribution's installed signing keyring. An ASCII-armored keyring must be dearmored into a private temporary verification directory before using gpgv; do not change the host signing keyring to accommodate this tool.

Choose a new workspace under an existing directory on Btrfs. The tool creates that workspace root-owned and private, copies the input archive there, verifies the private bytes, validates bounded archive paths and extracts only that copy. It never overwrites an existing workspace or formats a device.

```sh
sudo python3 tools/prepare_test_os.py extract \
  --workspace /path/to/new/test-os \
  --archive /path/to/archlinux-bootstrap-2026.10.01-x86_64.tar.zst

sudo python3 tools/prepare_test_os.py install-deps \
  --workspace /path/to/new/test-os
```

Dependency preparation initializes the guest's signing keyring and performs a full distribution update plus Python/Btrfs-tool installation. This is the only step that uses outbound networking. It writes the guest package database and files, and records the resulting package inventory in `dependencies.json`. Package versions can change between preparations; the pinned seed alone does not pin the final rolling distribution. The host package database, mount policy and startup configuration are not modified.

The guest uses a distinct 65,536-ID user namespace. Ownership is shifted on disk within the dedicated OS tree, rather than using an ID-mapped root mount. This matters on the tested kernel: the real defrag ioctl returned EPERM on an ID-mapped mount, consistent with the [kernel's use of an unmapped inode-permission check](https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/05e96e96a315fa49faca4da2aedd1761a218b616/fs/btrfs/ioctl.c#2588). The test retains user isolation instead of granting the guest host-root identity.

## Run the lifecycle test

```sh
sudo python3 tests/real_systemd_install.py --workspace /path/to/new/test-os
```

The guest is limited to 1 GiB memory and a CPU quota equivalent to two CPUs. Its qualification run has private networking and no host service-manager socket. The source payload is copied and verified, then bound read-only. A dedicated early guest service attaches the simulated controller after nspawn finishes assembling its API filesystem; a marker check refuses test writes when that fixture is absent.

The harness checks:

1. Fresh apply, repeat apply, active power service and active timer.
2. Real service stop/start restoration and the actual resume hook after a simulated controller reset.
3. One real maintenance-service pass against a private copied ELF library, with content verification and a 16 MiB submitted-work budget. Only the guest fixture scan policy is changed for this test; the original config is restored before removal.
4. Undo, repeat undo and reinstall.
5. A guest reboot with a fresh PID 1 and simulated controller reset, followed by enabled-service startup and policy reapplication.
6. Undo after that guest reboot and orderly guest shutdown.

`qualification-result.json` is written in the private workspace. A successful report includes source/harness hashes, userspace versions, the bounded worker result and explicit scope flags. New construction markers record persistent Btrfs identities for both workspace and guest directories, and later actions refuse replacements. See [the provenance guide](workspace-provenance.md) for guarded legacy migration before a restart and native remount/replacement evidence. The `INCOMPLETE` marker concerns dependency preparation; qualification success is established only by the result report.

The guest reboot is a container lifecycle transition. It does not reset the physical SSD or reboot the host kernel. The resource caps, simulated controller and copied workload make these correctness checks unsuitable for throughput or application-latency claims.
