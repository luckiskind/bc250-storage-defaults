# Native startup, persistence and reset trials

This lab qualifies independent writable trial copies of the [native B0/B1/B2 baselines](native-volumes.md). Each variant runs three launches of real guest systemd on the actual BC-250 kernel. It verifies an application/file mutation and SQLite state through orderly shutdown, unmount/remount and a new guest launch, then proves that a new copy resets the original tree. It does not reboot the physical host, discard its caches or measure speed.

## Clean input requirement

The startup audit found two enabled historical qualification services in the first userspace baseline set. Their scripts lived outside the copied source directories. Content/layout construction had passed, but that was not startup qualification. The original report and images remain preserved as earlier construction evidence.

The corrected builder removes only the exact known `bc250-qualification-reset.service` and `bc250-qualification.service` fixtures and their expected activation symlinks from **new image copies**. It validates the whole set before removing anything. An edited service or unfamiliar activation is preserved and fails construction; unrelated services are retained. The prepared source OS is unchanged. The new [clean baseline report](evidence/stage0-native-clean-volume-baselines.json) identifies the corrected producer and source hashes.

Each clean tree has 36,646 durable entries, 26,938 regular paths / 25,117 unique regular inodes, and 694,669,717 logical file bytes. All three have equal content/checked metadata hashes and separate filesystem UUIDs. This build's B2 pass verifies 45 files and charges 141,427,840 logical bytes with no retry bytes. Native writeback/layout outcomes can vary between fresh constructions; the recorded image and layout, not its label alone, define a trial input.

## Trial sequence

| Phase, for each B0/B1/B2 | Action and required evidence |
| --- | --- |
| Create | Independently copy the protected image; verify logical image bytes, absence of outer sharing/compression and full original tree. Install the lab probe only in that writable copy. Reach `multi-user.target`, run Python and OpenSSL, mutate the deterministic fixture, and commit a nonce/count in SQLite and a synchronized JSON record. |
| Persist | Orderly stop, synchronize and unmount the trial filesystem. Mount that same writable copy again and start a new guest. Require the original nonce, mutated file hash and SQLite count; update the durable count from 1 to 2. |
| Reset | Make a different independent copy from the protected baseline. Verify the full original tree and absence of trial state before adding the probe. Reach the usable target with a new nonce/count of 1 and the original fixture bytes. |

All nine probes require real guest systemd as PID 1, the expected copied filesystem UUID, the actual host kernel, mapped root ownership, private user/PID/network namespaces, an active usable target and **zero failed guest units at the checkpoint**. SQLite integrity and `synchronous=EXTRA` are checked. Each phase's bounded transient unit must exit before the driver remounts the image. Every protected baseline fingerprint must remain exactly unchanged.

The probe waits after `multi-user.target` with explicit dependency settings, so target ordering does not create a cycle that silently drops its job. The driver uses a separate transient service per guest launch. `systemd-nspawn --keep-unit --register=no` retains that service for its descendants rather than allocating a separate uncontrolled scope; see [systemd's unit-allocation contract](https://www.freedesktop.org/software/systemd/man/latest/systemd-nspawn.html#--keep-unit). The phase service joins only its live parent helper's private mount namespace.

## Protection and resource limits

Protected images are root-private, read-only regular files with recorded fingerprints. They are never mounted. Trial destinations are new regular files created exclusively, with NOCOW established before copying. Ordinary independent byte copies are used; the canonical image digest treats holes and allocated zero blocks equivalently while detecting changed nonzero bytes. Compression/shared extents are refused on the outer trial file.

A baseline-set lock prevents overlapping cooperating trial runs. Only one writable image for a given filesystem UUID is mounted at a time; the first copy is unmounted before its reset copy is mounted. Every fresh mount must match the original private tree inventory before probe injection. Existing outputs are never overwritten or silently resumed. Failed images, phase results and logs remain private for inspection.

The helper and each sequential phase have a 1 GiB memory limit, no swap and two CPU equivalents. Each phase has a 240-second runtime limit and control-group cleanup; the overall driver is bounded separately. Networking remains private and no host service-control socket is exposed to the guest. The actual NVMe policy is checked before/after and never changed. These limits apply to this lab; they are not NAND-write accounting or a cold-cache procedure.

## Reproduce

Build a new clean baseline set with the current matching producer; retain its `result.json` and root-private tree inventories. Old sets from a different producer are not silently reinterpreted.

```sh
sudo python3 tools/native_trial_lab.py run \
  --baselines /absolute/lab/clean-native-volume-set \
  --output /absolute/lab/new-native-trial-run
```

The output must be a new directory separate from the protected set. The driver prints its exact transient unit and compact per-variant progress. Guest console output stays in private logs. The final report is committed only after all variants pass. This does not apply the production installer or change the working installation.

## Accepted result and limits

The [accepted trial report](evidence/stage0-native-trials.json) passes all nine launches: three creates, three persistence relaunches and three independent resets. Durable counts follow 1 → 2 on each first copy and restart at 1 with a new nonce on each reset. Full original trees, file mutation persistence, SQLite integrity, usable targets, private namespaces, zero failed units and unchanged protected baselines all verify. The baseline-report bytes and executed source hashes are checked before publication. The suite passes 102 isolated Linux tests.

Container boot IDs change between these launches; the physical kernel does not restart. Orderly unmount/relaunch evidence does not establish crash durability, physical SSD cache behavior, host-cold cache state, graphics/game compatibility, driver reset or suspend/resume. No throughput or user-visible speed comparison was run. Private-lab/worker boot-dependent identity review and a known-good physical boot/recovery path remain open Stage 0 work before later measurement gates can close.
