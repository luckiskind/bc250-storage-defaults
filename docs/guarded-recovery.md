# Guarded recovery boot development

This work prepares the separate test/recovery root required by Stage 0. It does
not raise the physical PCIe link rate or establish a new throughput result.

## Selection and return guard

`tools/recovery_boot_guard.py` is installed only in an explicitly prepared
private candidate. Before writing its result it verifies the real systemd
environment, exact kernel/command-line nonce, persistent Btrfs root identity,
selected Limine entry, consumed one-shot request, and a read-only view of the
expected ESP/configuration. The default must name a unique Linux entry and
remembering the last selection must be disabled. The private fixture must match
its reference; the usable target must be active with no failed units.

After recording success it requests an ordinary reboot. On a service failure,
a separate return action repeats the boot-policy checks before requesting a
reboot. It does not write firmware variables, alter boot files or run storage
maintenance. Root-identity refusal happens before managed result writes. The
return action has no managed-data writes; that is not a claim that every earlier
failed action wrote nothing.

The [Limine configuration reference](https://github.com/Limine-Bootloader/Limine/blob/v12.x/CONFIG.md)
describes the precedence of one-shot selection, remembered selection and the
configured default. The [systemd Boot Loader Interface](https://systemd.io/BOOT_LOADER_INTERFACE/)
defines the EFI variable vendor and consumed one-shot request. A reported feature
does not establish a working physical return path.

## Isolated virtual matrix

`tools/uefi_recovery_vm.py` derives independent regular-file images from the
pinned actual-kernel bridge. It removes the exact known automatic VM poweroff
probe, adds the guard, and uses byte-verified copies of the installed kernel,
initramfs and Limine EFI binary. OVMF comes from the existing signed private
toolchain. No host firmware variables or block devices are passed to QEMU.

There are two normal/trial/normal sequences: one valid candidate and one with a
deliberately incorrect expected root identity. The second must refuse managed
writes and still return via independently verified boot policy. Normal and trial
roots have separate filesystem UUIDs; protected images stay read-only and each
case gets new writable overlays and private EFI variables. Trial results are
inspected read-only after return. QEMU has no NIC or shared host directory.

The initial continuous-QEMU run passed normal selection and the trial guard,
then stalled during the third boot after Limine announced initramfs loading.
That run and its logs were retained and stopped through its bounded parent
service. Its source baseline fingerprint remained unchanged. The cause is
unresolved. In-process warm reset is **not qualified**.

The revised matrix exits QEMU on each guest reboot request and starts a fresh
machine instance with the **same** case overlays and private persistent EFI
variables. This checks durable one-shot/default selection across cold machine
instances, not continuous-QEMU warm reset. Each boot has a four-minute deadline;
the whole parent has bounded CPU, RAM, swap and duration. These timings are not
performance measurements.

## Recorded result

The [reviewed evidence](evidence/stage0-guarded-recovery.json) passes both
three-boot cold-machine sequences (six UEFI boots total), with the one-shot
request consumed, normal return verified and fixture unchanged. The wrong-root
case writes no managed result. The guard uses the actual installed BC-250 kernel
and initramfs; protected images remain unchanged and test loop attachments are
gone. The Linux suite passes 114 tests. All seven live profile files still match,
power/timer stay active at 5000 us, daily charges were not rewound, the host boot
configuration is unchanged and no physical one-shot request is set.

Physical preparation also completed: a separate 58,000-node candidate has its
copied content/links/modes/normal ownership verified, the VM poweroff probe
removed, root-only mounts and a guarded return service. Its proposed boot config
is staged privately; physical entry and return remain untested.

## Physical preparation

`tools/prepare_physical_recovery.py` requires a passing six-boot UEFI report with
matching guard sources. It copies the protected minimal root into a newly
created, separate Btrfs subvolume. Content, hardlink groups, normal ownership,
modes, symlinks and regular-file modification times are compared before the
intentional candidate changes; security-xattr transfer is not qualified.

The candidate has a single root-only mount entry, fresh storage state, no
maintenance service and no VM automatic poweroff probe. Automatic GPT mount
discovery is disabled in the proposed trial command line. The existing working
kernel/initramfs are verified and referenced with their existing BLAKE2b file
checksums. The normal menu entry remains the proposed default, remembering the
last entry is disabled, and one flat trial entry is appended.

Preparation writes the original and proposed configuration **privately in the
lab**. It does not edit `/boot`, select an entry, write firmware variables,
reboot or suspend. This tool currently targets the exact qualified BC-250
kernel/layout, rather than arbitrary installations. All incomplete artifacts
are retained. The subsequent [physical trial](physical-recovery.md) completes entry/return
and restores the original boot configuration for this target. This preparation
tool itself still performs no boot-menu publication or reboot.

The owner reports no functional system suspend wake on this BC-250. No remote
sleep will be attempted; physical resume is outside the compatibility claim.
This does not affect the independent qualified 5000 us NVMe drive-idle policy.
