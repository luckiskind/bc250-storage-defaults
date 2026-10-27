# Physical reboot qualification

One orderly reboot of the actual BC-250 passes with the installed development
profile. This closes the physical reboot check, not the independent recovery,
suspend/resume or hardware power-loss checks. The original v0.1.0 release has not
been rerun as a separate installation.

## Recorded result

The [physical transition evidence](evidence/stage0-physical-transitions.json)
compares a synchronized private record before `systemctl reboot` with a fresh
record after SSH returned. The following checks pass:

- The kernel boot identity changed, establishing a host reboot rather than a
  service or container restart.
- All seven installed file hashes still match their manifest and their earlier
  bytes; the power service and maintenance timer are enabled and active.
- The actual NVMe latency tolerance is 5000 us. The new runtime power record
  captures an original tolerance of 100000 us.
- The kernel version, recorded root-subvolume path and boot configuration hash
  are unchanged. The existing Limine boot selection was used without editing
  the bootloader configuration or installing another kernel.
- Every previously recorded daily budget remains charged; no allowance was
  restored or reset to obtain this result.
- Three format-2 private OS trees still pass their persistent workspace/guest
  ownership checks. This includes the two migrated trees and the new seed tree.
- No STOP marker or pending installation transaction is present.

The read-only recorder and its dependencies have matching before/after source
hashes. The 109 isolated Linux tests also pass on the rebooted machine.

This is one boot on one controller/kernel configuration. It does not establish
boot-time performance, repeated-boot reliability, SSD internal-cache coldness,
application speedups or a separately booted recovery system. The production
worker and its policy were not changed for this test.

## Reproduce the records

`tools/physical_transition_probe.py` records evidence; it never initiates reboot
or sleep, sets alarms, changes services, repairs failures or resets a ledger.
It requires host root and writes new files under an explicit private output.
It refuses existing phases and unfamiliar output markers. Private records
include host boot identity and test-tree paths; only reviewed result files
should be redistributed.

After verifying backups, the selected boot entry and that the host is available
for a restart, record the before phase. Each optional `--test-os` must refer to
a previously authenticated format-2 private OS tree:

```sh
sudo python3 tools/physical_transition_probe.py before-reboot \
  --output /absolute/private-lab/new-transition-records \
  --test-os /absolute/private-lab/prepared-test-os
```

Only a healthy profile is accepted as a before record. Initiate the orderly
reboot separately using the system's normal service manager. After reconnecting:

```sh
sudo python3 tools/physical_transition_probe.py after-reboot \
  --output /absolute/private-lab/new-transition-records
```

The after phase uses exactly the previously recorded test-tree paths and writes
its result even if a comparison fails. Preserve failed records and investigate;
do not run a repair first and present the repaired state as automatic startup.
Use a new output for another reboot pair. `before-suspend` and `after-suspend`
are separate record pairs; a successful suspend verdict additionally requires
an unchanged boot identity, an increased kernel suspend-success counter and at
least one second of suspended time from BOOTTIME minus MONOTONIC. They do not
arm or verify a wake source.

## Awake alarm failure; suspend remains untested

The tested kernel exposes only `[s2idle]` in `mem_sleep`. The RTC is enabled for
wakeup and the `rtc_cmos` ACPI-alarm parameter reads `Y`. Nevertheless, an awake
`rtcwake --mode on --seconds 3` probe was still waiting after 34 observed seconds
on the earlier boot. It was interrupted and its alarm cleared. A bounded probe
after the physical reboot also timed out at 12 seconds and cleared its alarm.
No physical suspend was attempted.

`rtcwake`'s `on` mode waits for an alarm event without entering sleep; hardware
alarm support must not be inferred merely from a writable wake-alarm attribute.
See the [util-linux manual](https://www.man7.org/linux/man-pages/man8/rtcwake.8.html)
and [kernel RTC interface documentation](https://www.kernel.org/doc/html/next/admin-guide/rtc.html).
The cause on this firmware/kernel is unproven. This awake failure does not prove
that every ACPI sleep-wake path is broken. No RTC-driver parameter, interrupt
routing, firmware setting or kernel argument was changed to work around it.

A demonstrated automatic wake path or available physical wake assistance is
needed before a remote suspend attempt. When testing it, invoke normal system
sleep so the installed post-resume hook runs through the normal lifecycle;
do not substitute a direct write to the kernel sleep-state file. Systemd
[documents](https://www.freedesktop.org/software/systemd/man/latest/systemd-suspend.service.html)
its pre/post hook execution. A service restart or manually invoking the hook is
not a physical resume result.

## Remaining physical gates

The existing boot files and same-SSD read-only root reference are preserved as
described in [the provenance guide](workspace-provenance.md). The current Limine
12.9.0 reports one-shot entry selection support, but no boot-counting fallback;
that capability report is not a tested recovery boot. The subsequent [actual-kernel VM bridge](host-kernel-recovery.md) verifies the minimal recovery userspace with copied installed boot files and matching runtime modules. A separately verified
test/recovery entry and return to the working root remain open.

Physical write/metadata/lost-sharing accounting on disposable data, selected
native interruption cases and Stage 1 workload measurements also remain open.
No hardware power cut was performed against the working installation.
