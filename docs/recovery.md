# Interrupted installer recovery

This describes the development branch. The original v0.1.0 release does not contain this journal/recovery implementation.

## Operator procedure

1. Keep the source checkout used for the interrupted operation. Preserve `/var/lib/bc250-storage-defaults` and its journal before manual investigation.
2. Inspect `sudo sh status.sh`. A pending transaction blocks another apply/removal.
3. Run `sudo sh apply.sh --recover` from that matching checkout.
4. Inspect status again. Recovery with no pending transaction makes no service/file changes.

If recovery refuses an administrator edit/replacement, a missing ownership witness, unfamiliar partial contents or a service-stop failure, preserve those files and investigate. Do not delete the journal to bypass the refusal. An unrecorded partial staging write can be identified only against the matching package bytes; an updated checkout may be insufficient.

## Commit and ownership rules

The installer takes a private exclusive lock. Before changing destinations it persists a bounded, root-private transaction journal containing only the seven allowed installation paths. Each complete payload is written and fsynced to a new sibling staging file; its inode identity is saved before a hard link publishes the destination without overwriting an existing name. The staging name remains an ownership witness until commit. Activation intent is journaled before service control.

An active manifest with this transaction's identifier is the installation commit point. Recovery preserves that installation and finishes staging cleanup. Before that commit point it validates every remaining destination and staging file, stops/restores services if activation could have occurred, then deletes only proven owned files. Removing an installation journals ownership before stopping services, records successful shutdown before deleting helpers, and commits an inactive audit manifest after removal. A partially completed removal resumes forward.

An identical-content replacement with a different inode is still a replacement. Recovery preserves it and refuses the operation. Unfamiliar paths, symlinks, changed contents/modes and unsafe state directories are also refused. Hash verification alone is not used to justify deleting a replacement.

Journal/manifest replacement uses fsync on the file and its containing directory. File publication and deletion also synchronize their parent directories. Linux documents why [directory synchronization is required separately](https://man7.org/linux/man-pages/man2/fsync.2.html) and why [hard-link publication cannot replace an existing name](https://man7.org/linux/man-pages/man2/link.2.html). This ordering is a design property; it is not evidence that actual storage power-loss behavior has passed qualification.

## Evidence and limits

Thirty-six isolated Linux tests and a [40-case SIGKILL matrix](evidence/stage0-installer-crash-tests.json) pass. The matrix uses real installer operations and real Btrfs in a private user namespace, with simulated systemd and NVMe sysfs. It checks rolled-back/removed files, restored simulated power state, committed-install preservation and repeated recovery. It also checks refusal of a same-content administrator replacement.

SIGKILL leaves the kernel and filesystem running. These tests do not simulate volatile device caches, lost writes, reboot, actual service-manager recovery or interrupted recovery at every instruction. Those qualification gates remain open. Recovery does not restore the old extent layout or snapshot/reflink sharing of already repacked files. The working host installation is not a destructive fault-test target.
