# Independent native userspace baseline volumes

The native-volume lab creates B0, B1 and B2 on three separately formatted Btrfs filesystems. Each contains a complete prepared Arch userspace: `/usr`, `/etc`, `/boot`, the package database, a fresh empty home and other runtime directories, and a deterministic 32 MiB incompressible control. The source is the authenticated disposable OS from [the preparation guide](real-systemd-qualification.md), not the working host's configuration or home directory.

These are native, loop-backed filesystem images on the BC-250. The B2 worker executes through a private user/container namespace on the actual CachyOS host kernel, without QEMU or CPU emulation. This is an intermediate native measurement environment. It does not establish physical boot, suspend/resume, graphics/game compatibility, or a known-good hardware recovery path. Those remain separate Stage 0 work.

## Baseline contract

| Variant | File layout after construction | Drive policy required in a later comparison |
| --- | --- | --- |
| B0 | Fresh ordinary writes under Btrfs zstd:1 | Original recorded 100000 us |
| B1 | Fresh ordinary writes under Btrfs zstd:1 | Qualified 5000 us |
| B2 | Same fresh tree, then one bounded production-worker pass | Qualified 5000 us |

Construction never changes the host's controller setting. All three are built while its existing setting remains in force. Labels alone do not mean that the B0/B1 power comparison has been run. The original pre-study physical extents cannot be reconstructed from these fresh copies.

Each image has its own filesystem UUID and receives independent file writes, with no reflinks or shared data store between variants. Logical contents and supported metadata must match across all three after B2 conversion. The private inventory includes file hashes and mtimes, modes, mapped ownership, symbolic-link targets, hardlink topology and extended-attribute hashes. Volatile runtime directories are excluded. The full inventories remain private; the public report contains their aggregate hashes and layout evidence.

The B2 construction pass uses the unchanged production helper and its existing size/class/exclusion policy, foreground load/real NVMe quiet checks, 512 MiB pass allowance, 2 GiB UTC-day limit, 300-second work deadline and 64 GiB inner free-space floor. Its configuration, SQLite accounting and logs are bound under `/run` from a new private lab directory, outside the canonical image tree. It scans only the copied userspace. It must verify at least one conversion and demonstrate a smaller encoded extent in a candidate that previously exceeded 16 KiB. A deferral, STOP marker, content/metadata difference or absent conversion prevents certification of B2; incomplete images are retained.

The lab ledger is independent of the working host's production ledger. These limits count repacking submissions and retries; constructing the OS copies and their metadata adds separate I/O. They are not a total construction-write or NAND-write ceiling.

## Backing-file policy and limits

Each 80 GiB sparse image is a newly created regular file under a new root-private directory. Only that new file is passed to `mkfs.btrfs`. Before any data allocation, the builder sets NOCOW on the backing file, then verifies that its final extents are neither compressed nor shared. The inner Btrfs filesystem retains compression and checksums. This avoids an unreported second compression layer; it does not eliminate loop or outer-filesystem overhead. [Btrfs documents the relationship between NOCOW and compression](https://btrfs.readthedocs.io/en/stable/Administration.html).

Sparse virtual capacity is not reserved physical host space. Input payload is capped at 8 GiB, members at 100,000, and host free space must remain above the checked 72 GiB floor at construction boundaries. The top-level builder runs in a transient systemd unit limited to two CPU equivalents, 2 GiB memory and no swap. It requires a private mount namespace. The native worker has a separate 1 GiB/two-CPU container limit, no exposed host service manager and private networking. Image mounts are removed before the process exits, and completed baseline files become read-only.

Do not write benchmark outputs directly into the protected baselines. A future runner must create and verify independent writable trial copies, record the real controller state for each condition, and account for loop overhead, outer physical I/O and host page cache. No native throughput or cold-cache claim follows from successful construction. The builder's cache-warming reads are verification, not a benchmark.

## Reproduce

Prepare a completed authenticated OS with signed Python and Btrfs dependencies. Retain its provenance files and source tree. The current preparation guard still uses the guest directory's recorded device/inode identity, so a host restart can require investigation; do not edit its marker to bypass a mismatch.

```sh
sudo python3 tools/native_volume_lab.py build \
  --workspace /absolute/prepared-test-os \
  --output /absolute/lab/new-native-volume-set
```

The output parent must exist and contain no symlink components. Existing output is never overwritten or silently resumed. The builder prints a short result with the output directory. `result.json` is committed only after all three variants pass. `INCOMPLETE`, build logs, generated archives and private inventories remain available after a failure. Images and those private files are not release assets.

The generated archive retains package metadata and hardlinks. Only six explicitly named package-keyring Unix socket paths are excluded when they are actually sockets; unexpected special files still fail the source inventory. The first construction attempt stopped on these leftover runtime sockets before any image was created. Their exclusion has its own regression test. Ordinary files with the same names remain part of the durable inventory.

## Recorded construction result

The accepted [native-volume evidence](evidence/stage0-native-volume-baselines.json) has three distinct filesystem UUIDs and an equal aggregate tree hash. Each tree contains **36,650 durable entries**, **26,940 regular paths / 25,119 unique regular inodes**, and **694,670,218 logical file bytes**. All checked file extents are unshared. The B2 worker's direct probe verifies the actual BC-250 kernel, copied root UUID, mapped root ownership, private user/network namespaces and readable real NVMe counters.

| Variant | ELF candidates at least 1 MiB | Candidates with encoded extents above 16 KiB afterward | Allocated outer image bytes |
| --- | ---: | ---: | ---: |
| B0 | 50 | 50 | 416,661,504 |
| B1 | 50 | 50 | 411,930,624 |
| B2 | 50 | 4 | 514,277,376 |

B2 verifies 46 files and charges **142,885,416 logical bytes**, with zero retry bytes, within its 512 MiB pass allowance. The four remaining candidates are hardlinked and conservatively skipped. Contents and checked metadata match B0/B1 afterward. Outer allocation includes filesystem/image overhead and retained space; it is not useful compressed data size or physical bytes written to NAND. The greater B2 allocation is recorded rather than treated as an automatic space saving.

B0/B1 have equal per-candidate maximum encoded extent sizes in this set. That does not prove identical complete extent geometry. A causal power-only comparison must hold layout constant, for example by testing both policies on equivalent resets of the same protected volume. Do not assign every cross-volume timing difference to drive wake-up behavior.

The suite passes 95 isolated Linux tests, including the archive/socket-name regression. The accepted source hashes are pinned in the evidence. All seven working installed hashes still verify and the actual power service/timer remain active at 5000 us. No new controller policy or user-visible speed comparison was applied.

## Remaining qualification

Construction and content/layout checks precede native launch/persistence tests and Stage 1 measurements. Physical BC-250 startup/reboot/suspend/resume, a recoverable hardware boot path, workload definitions, cache-state procedures, tracing attribution, write amplification and broad user-visible performance remain unqualified. These volumes extend the earlier 15-file native data fixture; they do not replace those missing gates with synthetic throughput.
