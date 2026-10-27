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

An active manifest with this transaction's identifier is the installation commit point. Recovery audits its installed contents and remaining staging artifacts, reestablishes the committed power/timer activation intent, synchronizes startup links and finishes staging cleanup. It can repair a missing startup link from an older interrupted commit. Before that commit point it validates every remaining destination and staging file, stops/restores services if activation could have occurred, then deletes only proven owned files. Removing an installation journals ownership before stopping services, synchronizes disabled startup links before recording successful shutdown, and commits an inactive audit manifest after removal. A partially completed removal resumes forward.

Once a transaction has recorded inode ownership for rollback/removal, an identical-content replacement with a different inode is still a replacement. Recovery preserves it and refuses deletion. Unfamiliar paths, symlinks, changed contents/modes and unsafe state directories are also refused. Hash verification alone is not used to justify deleting a replacement.

New version 2 journals identify owned Btrfs files by full filesystem UUID and opaque export handle, including subvolume/inode generation. Device numbers and mount IDs are excluded from the persistent comparison. The [mount-order qualification](persistent-ownership.md) reproduces the previous refusal and verifies the repair plus strict identical-replacement/snapshot controls. Legacy version 1 journals retain their saved device/inode checks; a mismatch requires preserving evidence and investigation, not editing or automatically upgrading the identity.

Journal/manifest replacement uses fsync on the file and its containing directory. File publication and deletion also synchronize their parent directories. Startup-link changes synchronize both dependency directories and their parent before activation commit or completed shutdown is recorded. A synchronization failure prevents a successful commit; it is not suppressed. Linux documents why [directory synchronization is required separately](https://man7.org/linux/man-pages/man2/fsync.2.html) and why [hard-link publication cannot replace an existing name](https://man7.org/linux/man-pages/man2/link.2.html). This ordering is a design property; it is not evidence that actual storage power-loss behavior has passed qualification.

## Evidence and limits

One hundred and two isolated Linux tests and the [latest 40-case SIGKILL matrix on the persistent-identity module](evidence/stage0-persistent-ownership-process-crashes.json) pass. The matrix uses real installer operations and real Btrfs in a private user namespace, with simulated systemd and NVMe sysfs. It checks rolled-back/removed files, restored simulated power state, committed-install preservation and repeated recovery. It also checks refusal of a same-content administrator replacement. The earlier matrix remains preserved as historical evidence.

The process-only SIGKILL matrix leaves the kernel and filesystem running. A separate [seven-case VM profile suite](evidence/stage0-virtual-profile-faults.json) passes eight acknowledged whole-guest interruptions and 15 boots using real guest systemd, including an interrupted recovery. It found and reproduced the service-link durability failure described in [the virtual fault guide](virtual-profile-faults.md). The repaired committed case checks startup before recovery and separately tests repair of an explicitly removed timer link. Neither suite simulates volatile device-cache loss, torn writes or every possible instruction boundary. A separate [calibrated cache model and selected installer VM case](volatile-cache-faults.md) now exercise positive software device-cache loss. The [worker matrix](worker-cache-recovery.md) now also qualifies three selected worker boundaries and conservative charges. Broader device-fault/recovery interleavings and physical boot/resume/power-loss remain open. Recovery does not restore the old extent layout or snapshot/reflink sharing of already repacked files. The working host installation is not a destructive fault-test target.
