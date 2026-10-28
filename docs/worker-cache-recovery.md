# Repacker recovery and conservative work accounting

This Stage 0 development qualification runs the actual worker in a separately booted Btrfs VM, then loses both guest state and pending writes in the [calibrated volatile disk model](volatile-cache-faults.md). It checks content and resource-accounting correctness. It is not a native throughput benchmark or physical SSD power-loss qualification.

## Qualified paths

The fixture is a full 6,344,456-byte ELF library copied into a new private test image. Its source hash, expected content hash, configuration and kernel/initramfs hashes are recorded. Each scenario starts from a separate ordinary sparse byte copy of the protected baseline, without reflinks. The worker scans only that fixture directory.

The test config sets a 7,393,032-byte pass allowance and a 14,786,064-byte daily allowance: one full-file attempt plus the normal 1 MiB retry cap, and room for one recovery attempt. The normal 64 GiB free-space floor remains. Fixture age and load thresholds are test-specific. The production loop still performs its real idle check: a narrowly scoped test adapter maps its NVMe-stat pathname to the live `/sys/block/vda/stat` counters of the VM's actual root disk. It does not supply constant or fabricated counters.

The guest imports the unchanged repacking algorithm from the exact recorded helper. Instrumentation announces selected boundaries on the serial console without writing a checkpoint file or adding a sync there. The host arms the disk model to cut after its next ordinary write reply, proves positive pending-byte loss, kills its tracked QEMU process, and boots the same stable image with a fresh disk process.

| Scenario | Interruption | Required result |
| --- | --- | --- |
| Baseline | Orderly worker run and repeat | Full content/layout verification and unchanged budget on repeat |
| Reservation | Immediately after the reservation commits, before the first layout syscall | Reservation and its UTC day survive exactly; uncertain work remains charged |
| Mid-processing | After eight real range-sync operations | Original content and file metadata survive; the existing reservation is retained during recovery |
| Verified, before final charge | After the worker verifies the file, before `finish_budget` runs | Verified layout can be recognized without rewriting; the uncertain original reservation is not refunded |

Recovery checks SQLite integrity, the exact original reservation and the equality between recorded daily work and conservative attempt charges. It runs the actual worker in fresh subprocesses, verifies the file hash and metadata, then repeats maintenance and checks that neither attempts nor charges increase. A content-verified layout miss remains an explicit miss; the harness does not relabel it as successful repacking.

## Commit-policy hardening

The worker now explicitly requests SQLite `synchronous=EXTRA`, reads it back, and accepts only the supported DELETE or WAL journal modes. It refuses to repack if that policy cannot be established. It also synchronizes the state directory's parent before ledger reservations can authorize mutations elsewhere.

SQLite documents that rollback-journal FULL synchronization can preserve consistency without guaranteeing that the last commit survives power loss. EXTRA additionally synchronizes the journal's directory after deletion. This is a documented durability-contract gap being hardened, not a claim that the previous worker lost a reservation in these tests. See [SQLite's synchronization contract](https://www.sqlite.org/pragma.html#pragma_synchronous). The ledger schema and existing charges are retained; the setting is established on each connection.

The work limit counts logical repacking submissions and bounded retries. It is not a NAND-write limit. SQLite, filesystem metadata, lost sharing and physical write amplification still require separate measurements.

## Reproduce

Prepare the dedicated signed-package toolchain in [the virtual-lab guide](virtual-recovery.md), and complete the matching [cache-model calibration](volatile-cache-faults.md). Build a new worker image; changing the worker or embedded guest source requires a new artifact label.

```sh
sudo python3 tools/virtual_test_lab.py worker-build \
  --workspace /path/to/vm-test --artifact-label worker-v1
sudo python3 tools/virtual_test_lab.py worker-test \
  --workspace /path/to/vm-test --artifact-label worker-v1 --run-label worker-01 \
  --calibration-report /path/to/vm-test/vm-cache-calibration-cache-v1-calibration-01.json
```

The default matrix runs the baseline and three interruption scenarios. `--cases baseline` is a fixture/worker check, not fault coverage. Other selected cases are `reserved`, `range-sync-8`, and `verified-before-finish`. Existing images and run directories are preserved. The parent remains limited to two CPU equivalents and 2 GiB memory, with a 768 MiB VM and 64 MiB modeled disk cache. Failed images and escaped console logs remain private.

## Recorded results and remaining gates

The accepted matrix passes all four scenarios across seven boots. The three cuts discard **48 KiB, 108 KiB and 48 KiB** respectively. All resulting fixture layouts reach 16 KiB compressed extents with matching content hashes. The reservation and mid-range cases retain the old full reservation plus one newly completed attempt; the pre-final-charge case recognizes the completed layout and retains only the full old reservation. Repeated passes leave charges unchanged. The expanded unit suite passes 79 tests.

The live helper is backed up and updated with configuration/history intact, all seven installed hashes verified and DELETE/EXTRA read back. A disposable layout/content check passes. Its normal service pass does no further work because the UTC-day remainder is 643,253 bytes, below the 1 MiB minimum. This is compliance with the existing limit, not a newly timed repacking result. Power and timer services remain active at 5000 us.

The accepted [worker VM evidence](evidence/stage0-worker-cache-vm.json) and [live deployment verification](evidence/stage0-worker-ledger-live.json) identify their tested source and exact scope. The source-payload installation rerun is recorded separately in [the 40-case process matrix](evidence/stage0-worker-ledger-process-crashes.json). Source hashes and the unchanged calibration prerequisite bytes are checked before publication.

The installed reliability repair preserves configuration and ledger history. Root-private backups include the previous helper, manifest and a consistent SQLite backup. A rollback must restore only the intended helper/manifest after verification; rewinding an old ledger would forget charges and is not part of ordinary rollback. A STOP marker must be investigated, never cleared to force another pass.

The calibrated model cuts between requests; partial barriers, torn writes and firmware/NAND failures are outside its scope. One ELF fixture and three worker boundaries do not establish every possible crash ordering, concurrent application write, snapshot/reflink or hardware behavior. Broader installer/recovery faults, independent native baselines, physical boot/resume/recovery and physical-write/metadata/sharing measurements remain open Stage 0 work. No new performance gain is claimed here.
