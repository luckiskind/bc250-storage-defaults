# Recovery userspace with the BC-250 boot artifacts

The minimal recovery OS now passes three VM boots using copies of the actual
BC-250 kernel and installed physical initramfs. This is a compatibility bridge
toward an isolated physical test/recovery entry. It does not qualify that entry,
the firmware path, actual device drivers or suspend/resume.

The artifact still includes a VM probe that powers off its guest after testing.
Do not select it as a physical boot target. Deriving a hardware candidate requires
removing that exact fixture, configuring a controlled return to the working
entry, and validating the resulting candidate separately.

## What passed

The [recorded matrix](evidence/stage0-host-kernel-vm.json) uses
`7.2.8-1.219-cachyos-bore-bc250`, the same kernel release as the working host.
The kernel and initramfs bytes match copies of the installed boot files. A
separate guest kernel instance boots each time; guest boot identities differ
from the host and from each other.

| Phase | Storage | Durable count | Result |
| --- | --- | ---: | --- |
| Initial launch | VirtIO block | 1 | Usable target active; zero failed guest units |
| Same overlay, new kernel instance | Emulated NVMe | 2 | Prior nonce/state and fixture bytes retained |
| Fresh overlay | Emulated NVMe | 1 | Prior state absent; new nonce; fixture unchanged |

The VM baseline comes from the protected minimal distribution image used in
[the earlier separate-kernel recovery lab](virtual-recovery.md). The builder
checks that original image against its passing reference fingerprint before
copying. It mounts only a newly created independent regular-file copy, and the
guest filesystem identity must differ from the working host's filesystem.

Only that copy changes: the root mount entry uses its filesystem UUID instead
of a VirtIO-specific device name, the known probe gains a usable-target and
failed-unit check, and the exact known probe unit gains explicit dependency
ordering. Unknown source contents cause refusal. The matching runtime module
tree adds 7,739 entries and 182,300,140 logical file bytes; file bytes, modes,
UIDs/GIDs and symlink targets match their captured source inventory. Build
headers and module sources are omitted. This is not a security-xattr or complete
metadata-preservation qualification.

Both the original reference and the new VM baseline remain unchanged through
the boot matrix. The public evidence also pins a post-run artifact manifest,
captured without modifying the tested images, for subsequent derivation. Its sparse fingerprint covers size,
non-hole range geometry and data bytes, not a SHA-256 of all 80 GiB of logical
capacity. No protected image is mounted directly. The test copy is unmounted
before QEMU starts; no loop remains attached after completion.

All seven installed working-profile hashes still match their manifest. The
power service and timer remain active with actual controller tolerance 5000 us.
The 109 isolated Linux tests pass. The working profile, bootloader configuration,
firmware variables and kernel installation are unchanged by this matrix.

## Reproduce

Use a prepared, authenticated VM-toolchain workspace and a protected minimal
image whose three-boot/reset reference passed. No package update is performed.
Choose a new output directory on Btrfs with at least 72 GiB free:

```sh
sudo python3 tools/host_kernel_vm_probe.py run \
  --workspace /absolute/private-lab/vm-toolchain \
  --baseline /absolute/private-lab/vm-toolchain/artifacts/verified/baseline.raw \
  --reference-report /absolute/private-lab/vm-toolchain/vm-recovery-verified-run.json \
  --output /absolute/private-lab/new-host-kernel-vm
```

The host must use the tested boot-file layout: the running kernel's `pkgbase`
and machine ID locate its installed `vmlinuz` and `initramfs` files. The helper
does not create or edit boot entries. It rejects unsafe source paths, writable
or nonregular reference images, changed fingerprints, unfamiliar fixture
contents and existing outputs.

The parent runs in a private mount namespace with a two-CPU quota, 2 GiB memory
ceiling, 1536 MiB memory-high threshold, no swap and a 25-minute runtime limit.
The prepared mapped userspace supplies QEMU; the host package database is not
changed. Each software-emulated VM has 768 MiB RAM, no NIC, no host filesystem
passthrough and only regular image files as storage. Each boot has a five-minute
deadline. Failed artifacts and logs are retained. Inspect serial logs as escaped
text; do not print raw terminal-control sequences into a privileged shell.

The result file omits raw guest filesystem/boot identities, nonces, machine IDs
and private paths. Private phase records and serial logs retain diagnostic
details. Review results before redistribution. Software emulation and file-backed
I/O make the elapsed times unsuitable for performance comparisons.

## Remaining path to physical recovery

1. Derive a separate physical candidate from the verified minimal userspace,
   with its own root selection and storage state. Preserve the working root.
2. Remove the VM-only shutdown fixture, supply required hardware firmware, and
   validate a guarded return to the known working entry. Networking is not
   qualified by this NIC-free matrix.
3. Stage and review the physical entry without replacing the existing kernel,
   default boot selection or preserved boot-file backup.
4. Demonstrate entry into the test/recovery root and return to the working root,
   with physical assistance available if the firmware/kernel path fails before
   the return service can run. Limine reports one-shot selection but no
   boot-counting fallback; those are capabilities, not a tested recovery result.
5. Record target sleep compatibility. The owner confirms that this BC-250 has
   no functional suspend wake, so no remote sleep will be attempted. Physical
   resume remains unqualified and outside the target's compatibility claim;
   it does not block the remaining recovery/workload stages. See the
   [target limitation](physical-transitions.md).

The [guarded-return development guide](guarded-recovery.md) describes the next
UEFI selection matrix and a preparation-only builder for a separate physical
candidate. That work retains the continuous-QEMU warm-reset failure explicitly;
it does not turn the three-boot bridge above into a qualified physical entry.

Physical write/metadata/lost-sharing accounting and the Stage 1 workload and
cache-state gates remain separate. No throughput improvement, physical NVMe
power-state transition or hardware power-loss result is claimed.
