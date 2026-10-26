# BC-250 storage defaults (experimental)

Apply the tested drive power setting and a bounded Btrfs layout prototype with one command. This is a standalone system profile; it needs no game launch options and installs no driver or kernel patch.

## Apply

On the BC-250:

```sh
git clone https://github.com/luckiskind/bc250-storage-defaults.git
cd bc250-storage-defaults
sh apply.sh --check
sudo sh apply.sh
```

`--check` is read-only. Applying checks dependencies, refuses conflicting files, validates the exact repacking operation on a disposable Btrfs fixture, then enables the power service and maintenance timer. Applying the same version again verifies its files and enables its startup units. No reboot is needed.

This first release deliberately supports the tested configuration: **x86_64 Linux/systemd, nvme0 = PNY CS2241 1TB SSD, PCIe 5 GT/s x2, writable Btrfs for `/`, `/usr`, `/home` and `/var/lib`, at least 64 GiB free**, Python 3.10+, libzstd, `findmnt` and `systemd-analyze`. Tested kernel: `7.2.8-1.219-cachyos-bore-bc250`. The disposable test rejects kernels that cannot produce verified 16 KiB compressed extents. Other drives/layouts need their own qualification before changing the guard.

Keep the checkout for status and removal:

```sh
sudo sh status.sh
sudo sh undo.sh
```

Undo disables the timer, stops maintenance, restores the captured drive latency tolerance, and removes only owned, checksum-matching installed files. Administrator edits cause refusal before services are stopped. Repacked files remain normal valid Btrfs files. **Undo cannot reconstruct their previous extent layout or reflink/snapshot sharing.** Audit state is retained.

## What gets applied

| Setting | Default |
| --- | --- |
| NVMe latency tolerance | 5000 microseconds; reapplied on boot and resume |
| Native Btrfs layout | zstd level 1, compressed extents of at most 16 KiB |
| Scope | Eligible stable ELF binaries under `/usr`, `/opt`, `/home`, `/srv`, `/var/lib/flatpak` |
| Limits | 512 MiB/pass, 2 GiB/UTC day, 5 minutes/pass, 64 GiB free-space floor |
| Scheduling | About hourly, first check after 10–15 minutes; low CPU/IO priority |

The power setting excludes the tested drive's deepest slow sleep state. It does not disable all sleep. It can increase idle power use.

The prototype gradually repacks existing compressible files through Btrfs's defrag ioctl. It **does not set a universal 16 KiB policy for future writes**. Ordinary writes retain the existing mount policy, and stable eligible replacements become candidates on later passes. Non-ELF game archives/assets are outside the current validated class. No universal game-loading uplift is claimed.

Before a pass, the worker checks CPU load and waits for low activity on `nvme0n1`. It skips recently modified files, hardlinks, symlinks, privileged binaries, explicit NOCOW/uncompressed/protected files, sparse/unsupported extents and poor compression samples. File sizes are limited to 1–256 MiB. It checks SHA-256 before/after every repack, verifies compressed extent sizes and preserves owner/mode. A stable content mismatch creates a `STOP` marker and halts future passes. Hash verification detects a failure; it is not a backup or an automatic repair mechanism.

**Repacking writes data and can break snapshot/reflink sharing, increasing space use.** Keep backups and adequate free space. Maintenance begins when the drive is quiet but can overlap a later foreground workload; scheduler priorities and budgets limit its impact. This remains experimental filesystem maintenance.

## Configure and inspect

Installed configuration: `/etc/bc250-storage-defaults.json`. Edit it after installation to adjust scan roots, exclusions or budgets. Settings are read on each pass. Leave the tested file-class and hardware guards in place unless doing further validation.

```sh
systemctl status bc250-nvme-power.service bc250-btrfs-repack.timer
journalctl -u bc250-btrfs-repack.service
sudo systemctl start bc250-btrfs-repack.service   # optional: request one bounded pass
sudo systemctl disable --now bc250-btrfs-repack.timer
```

The worker being **inactive (dead), Result=success** between timer runs is normal. Its service sandbox grants explicit write access to the binary directories so that it can change physical extents. It needs root; it does not install credentials, change mount options, disable snapshots, change CPU power policy or tune game settings.

Files are installed under `/usr/local/libexec/bc250-storage-defaults`, `/etc/systemd/system`, `/etc/bc250-storage-defaults.json`, and `/usr/lib/systemd/system-sleep/90-bc250-nvme-power`. Root-only runtime/audit state lives under `/run/bc250-storage-power.json` and `/var/lib/bc250-storage-defaults`. If installation fails after activation, it attempts to stop/disable all its units before removing helpers; if stopping fails, files are retained for recovery. A power loss during installation may require inspection of the retained manifest/files.

Existing earlier lab installations are detected and never overwritten. They can be inspected with `status.sh`. Keep their original undo tool for an intentional migration; this project's undo also accepts their manifest if all owned paths/checksums still match. Downloading this project does not change an already running lab installation.

## Use as a source patch

Installation uses `apply.sh`; there is no kernel rebuild. To copy the whole small project into another source tree as one patch, run this inside a checkout:

```sh
python3 make_patch.py /tmp/bc250-storage.patch
cd /path/to/other/repository
git apply --check /tmp/bc250-storage.patch
git apply /tmp/bc250-storage.patch
sudo sh bc250-storage-defaults/apply.sh
```

The generated patch adds a `bc250-storage-defaults/` directory and does not alter the receiving repository's existing files. Remove the installed OS profile with `undo.sh` before deleting that source directory.

See [VALIDATION.md](VALIDATION.md) for measured results and test coverage. Code is MIT licensed.
