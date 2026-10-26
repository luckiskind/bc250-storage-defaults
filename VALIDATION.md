# Validation and limits

## Measured on one BC-250

Hardware: PNY CS2241 1TB, PCIe 5 GT/s x2; CachyOS kernel `7.2.8-1.219-cachyos-bore-bc250`; Btrfs zstd:1. The link itself remains hardware limited. Compression can increase logical bytes delivered per second by reducing bytes crossing that link; incompressible data remains limited to approximately 790 MB/s.

After 2.5 seconds idle, the tested drive's first 4 KiB read took approximately 21–22 ms with its original 100000 us tolerance and 1.75–2.27 ms with 5000 us. These are controlled idle/read measurements, not a count of sleep events during gameplay. Actual suspend/resume and reboot behavior of the packaged release remain untested; the original installed service was tested with stop/start.

A clean filesystem matrix compared nine representations, six read workloads and three repetitions: 486 read runs, plus 216 later CPU wake-policy checks. Earlier exploratory timings overlapped a CPU latency test and are excluded. The data set was 29 copied ELF files, approximately 2 GiB, plus an incompressible control. Content hashes were verified.

Native 16 KiB zstd:1 Btrfs repacking versus the original zstd:1 layout gave these median throughput changes on that corpus:

| Workload | Change |
| --- | ---: |
| Sequential, 1 thread | +13.2% |
| Sequential, 4 threads | +16.6% |
| Random 4 KiB, 1 thread | +53.7% |
| Random 4 KiB, 4 threads | +27.0% |
| Random 64 KiB, 1 thread | +34.7% |
| Random 64 KiB, 4 threads | +15.2% |

Sequential logical throughput reached about 1195–1225 MB/s. The incompressible control did not gain. Smaller compressed extents reduce random-read decompression amplification but may reduce compression efficiency and increase metadata. These results do not establish improvements for every application, game asset archive, filesystem or SSD. Queue/scheduler experiments found no broad validated improvement, so those changes are not packaged.

The earlier persistent lab deployment verified 211 files (1,072,514,930 logical bytes) before this reusable packaging work. That deployment history is separate from the tests below. The source retains the same defrag operation, power target, scheduling policy and eligibility limits, with portable installation and disposable validation replacing personal lab paths.

## Packaged source checks

- 15 isolated Linux tests cover repeat apply/undo, existing file preservation, administrator edits, unknown manifest paths, failed activation cleanup, keeping helpers if stopping fails, simulated controller reset, power-policy conflicts, unsupported drive refusal, hash-mismatch STOP handling, deadline bounds and file-class exclusions.
- Read-only compatibility check passed on the BC-250.
- The shipped self-test passed on the BC-250: it repacked a newly created 2 MiB private fixture, verified SHA-256 `e45d63f8863fb93f739ffd798351ddaca397bd7142c73e5fc02a1641084e29c5`, and reported maximum compressed extent size 16384 bytes. It removed the fixture afterward. The installer runs this before enabling any service. Systemd unit verification also passed.
- Installer/undo tests mock systemd and use temporary files. They do not uninstall or replace the already deployed lab defaults. A fresh complete installation in a second clean OS is not yet qualified.
- CI checks Python/shell syntax, isolated tests and whether the exported add-only source patch applies cleanly. CI does not claim real NVMe or Btrfs performance testing.

Run isolated checks on Linux:

```sh
python3 -m unittest discover -s tests -v
python3 tests/live_check.py /path/to/writable/btrfs/scratch
```

The live check changes only its disposable fixture. It does not alter services, real program files, power settings or the existing maintenance state. Keep performance validation separate from ordinary CI; virtual/cloud disks do not reproduce the target link or NVMe sleep states.
