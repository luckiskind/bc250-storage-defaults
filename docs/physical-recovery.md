# Physical private-root entry and return

The [recorded physical test](evidence/stage0-physical-recovery.json) passes on
the BC-250: working root → separate prepared Btrfs root → working root. This
closes the immediate physical boot gate in [Stage 0](evidence/stage0-gate.json).
The full accelerator goal remains active; Stage 1 measurement work has started.

The trial uses the installed `7.2.8-1.219-cachyos-bore-bc250` kernel and initramfs
without replacing either. Three distinct kernel boot identities establish the
before/trial/returned systems. The private root reaches real systemd's usable
target with zero failed units, verifies its persistent root identity, selected
entry, consumed one-shot, normal-default policy and unchanged fixture, writes a
durable result and requests an ordinary reboot. System suspend is not used.

After return, the controller verifies the original root, kernel and seven-file
profile and restores only the exact temporary configuration it published. All
before/after checks pass: original boot-menu bytes and remembered normal entry,
absent one-shot, enabled/active power service and timer, actual 5000 us controller
policy, retained quota reservations and captured original power value 100000 us.
The Linux suite passes 121 tests after return. Three private OS provenance records
remain accepted. The off-device boot archive checksum and same-SSD reference's
read-only property were also rechecked.

## Controller and procedure

`tools/physical_recovery_trial.py` controls this explicitly disruptive test. It
requires the exact prepared target/layout and root privileges. Keep the matching
tested source checkout for restoration. First use the [candidate preparation
procedure](guarded-recovery.md); choose a new private result directory:

```sh
sudo python3 tools/physical_recovery_trial.py preflight \
  --candidate /absolute/private-lab/new-physical-candidate \
  --output /absolute/private-lab/new-physical-trial
```

Preflight rechecks the complete prepared tree, support hashes, persistent root
identities, original boot files, staged configuration, current EFI selection and
profile health. It creates persistent journaling only in the private candidate
and records the resulting staged tree fingerprint. The actual boot setup stays
unchanged. The candidate and working root are separate subvolumes on the same
SSD; this is not device-failure redundancy.

After reviewing those records and ensuring the machine can be restarted:

```sh
sudo python3 tools/physical_recovery_trial.py boot \
  --output /absolute/private-lab/new-physical-trial
```

This publishes the checked temporary menu, fsyncs it, sets and reads back a
one-shot trial request, then requests a real host reboot. The normal Linux menu
path is the temporary default and remembering the last entry is disabled.
Limine updates its remembered path even with remembering disabled; the returned
normal boot must restore that remembered path before the original remembering
policy is restored. See [Limine's implementation](https://github.com/Limine-Bootloader/Limine/blob/v12.x/common/menu.c).
No firmware boot order or kernel file is replaced.

On reconnecting to the normal root:

```sh
sudo python3 tools/physical_recovery_trial.py verify \
  --output /absolute/private-lab/new-physical-trial
```

Verification requires a distinct trial result and restored working-root context.
It compares the profile/history before and after, restores the exact owned
temporary boot configuration and records the final result. A trial-result
failure is retained and reported rather than turned into success by restoration.

The separate `restore` operation can clear the owned trial request and restore
the owned menu while on the original root. Unknown edits, a foreign remembered
selection, a foreign root or another pending request are preserved and refused.
The file helper checks contents before writing and immediately before atomic
replacement; it does not provide a filesystem compare-and-swap guarantee against
an administrator writing in the final check/rename window. Do not run concurrent
boot-menu edits or package/bootloader updates during this qualification.

The controller creates its durable private record before boot-menu publication.
Failed/interrupted records and temporary files are retained. A pending record
is not a passed result. Do not delete it merely to repeat a run. The candidate's
guard is intentionally single-use: it refuses an existing managed result on
another trial. Keep the used candidate as evidence and derive a fresh independent
candidate for another controlled test.

## Scope and remaining limits

This demonstrates orderly physical entry into the minimal test userspace and
automatic return. It is not a complete interactive rescue distribution, an
off-device copy of user data, a physical power-loss test, a universal firmware
qualification, or a performance comparison. A firmware/kernel hang before the
return service still needs an external reset; one-shot selection is not a
hardware watchdog. The continuous-QEMU third-boot stall remains unresolved;
its virtual failure and this physical result are recorded separately.

The owner confirms no functional system suspend wake on this target. Physical
resume remains outside its compatibility claim. That limitation does not change
the independent qualified NVMe drive-idle policy.
