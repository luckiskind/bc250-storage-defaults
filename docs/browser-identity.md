# Stage 1 authenticated Firefox mapping observation

Status: two final-source Firefox launches pass the unchanged functional audit,
with an authenticated, temporary root observer. Each capture samples 15 owned
processes across three mount namespaces. It verifies the actual main executable
and records 209 distinct host objects matching pinned mapping references.
Complete input closure, cold-cache Firefox and performance remain unqualified.

## Scoped observation without browser privileges

`bench/browser_identity.py` keeps the [Firefox input audit](browser-inputs.md),
endpoint and page sources unchanged. A root orchestration unit creates a new
private corpus/report directory and a separate desktop-user output directory.
The user manager launches the browser audit in one fixed, randomly named test
unit, with private profiles and loopback-only IP networking.

The root observer listens on a private filesystem Unix socket. Its immutable
configuration fixes the desktop UID, expected unit name, nonce and observer PID.
The wire protocol accepts exactly `nonce` and `phase`; there is no target PID,
filename or caller-selected cgroup. It accepts only two ordered captures and a
finish request, all from the same controller inside that expected trial group.
Peer credentials, group membership and the actual process UID are checked before
mapping collection. Process/root/mapping descriptors then provide the
[qualified mapping-reference check](mapped-identity.md).

The client verifies the root observer's PID and UID. Inside its unprivileged
user namespace, unmapped host root appears as the kernel's overflow UID; this
translation is checked rather than assumed to remain UID zero. Root stays in
the initial user namespace. The actual browser main has zero effective,
permitted and ambient capabilities in each capture. Capabilities of every
other sampled helper are not claimed to be zero. No GUI capability or sandbox
setting is changed for observation.

Five live negative requests are rejected: a root outsider has the wrong UID;
the desktop user outside the fixed trial has the wrong scope; the legitimate
controller then sends a wrong nonce, an extra target-PID field and a replayed
capture phase. Rejections occur before mapping collection for that request.
Only aggregate summaries and a digest of the private capture return to the
client. Root-only raw reports retain process identifiers, mapping ranges,
namespace/root descriptions and per-object identity details.

This is a temporary trusted-lab protocol. Qualification covers these recorded
scope/authentication cases; production service hardening remains open. The
observer is not installed as a daemon, and the transient socket is removed.

## Two relationships, measured separately

The final observer records both:

1. Whether the observer's host pathname identifies the pinned actual mapping
   object, using live descriptor metadata.
2. Whether lookup through the process's current root view exposes that same
   object at the displayed path.

Neither comparison substitutes raw maps device/inode fields for the actual
mapping reference. The second relation may remain unresolved while the first
is verified. It never becomes a verified process-root alias merely because the
host object matches.

| Per capture | First launch | Second launch |
| --- | ---: | ---: |
| Process samples | 15 | 15 |
| Mount namespaces | 3 | 3 |
| Unique host objects matching mapping references | 209 | 209 |
| Mapping rows with that host/reference match | 4,431 | 4,431 |
| Unique objects with both host and process-root matches | 172 | 172 |
| Rows with both matches | 1,542 | 1,542 |
| Unresolved process-root view rows | 2,889 | 2,889 |
| Nonregular view rows | 13 | 12 |
| Processes with proc-fdinfo roots | 6 | 6 |
| Unavailable process samples | 0 | 0 |

Rows are virtual-memory mappings, not unique demanded bytes or physical reads.
Repeated segments/processes can refer to the same object. Observations remain
non-atomic. Deleted/anonymous mappings and transient activity remain outside
the supported regular-file association.

Private review found ESRCH for the unresolved root lookups. Six sampled roots
pointed to proc `fdinfo` directories. Mozilla's [sandbox launch source](https://github.com/mozilla-firefox/firefox/blob/main/security/sandbox/linux/launch/SandboxLaunch.cpp)
describes chrooting into a helper's proc-fdinfo directory, which becomes empty
and unlinked after that helper exits. The target observations match this
mechanism. Unresolved view aliases remain unresolved; the browser's normal
sandbox is retained. This also shows why mount-namespace ID alone cannot
describe a process's filesystem root.

## Bounds, cleanup and validation

The root observer unit has a 512 MiB memory limit, no swap allowance, 100% CPU
quota, 64-task limit and 240-second lifetime. Collection admits at most 64 trial
processes per capture. Each process's maps input is bounded to 1 MiB and 8,192
objects. The separate browser unit retains its 3 GiB memory limit, no swap,
512-task limit and 180-second lifetime; it has no requested CPU quota. The two
units' budgets are distinct and additive. IPC frames remain bounded to 4 KiB.

Both functional launches pass with identical initial private profile seeds.
After normal endpoint measurement, the unchanged audit uses SIGTERM cleanup
and tracer exit-kill behavior. Finish is accepted only when the test group
contains its controller alone; all owned browser processes are gone. This does
not qualify graceful Firefox quit or profile durability.

The first integration passed and recorded the root-view limitation. A second
retained run added the separate host/reference relation and proc-root
description. The final source scopes its capability claim to the checked main
process. Earlier artifacts remain; timings are not pooled or promoted.
The revised mapping module also passes all four native Btrfs controls again,
including the raw maps identity collision. The original failures stay failed.

The Linux suite passes 157 tests. New tests reject incorrect schema, UID,
nonce, order, scope and controller before acceptance, and check root credential
translation. A separate unit check proves that host/reference matching is
independent of the process-root relation. Syntax verification uses a private
user-owned bytecode prefix. Seven installed file hashes, original boot
configuration, active power/timer, 5000 us policy and quota history verify.
[Reviewed evidence](evidence/stage1-browser-identity.json) contains aggregates,
source hashes, native regression results and explicit incomplete gates.

## Reproduction and next work

Use the authorized desktop session, matching sources and new private outputs:

```sh
sudo python3 -B bench/browser_identity.py run --uid 1000 \
  --output /absolute/owned-lab/new-browser-identity \
  --desktop-output /absolute/owned-lab/new-browser-desktop
```

Observer collection occurs after the functional ready marker and adds work to
the audit. It is not an overhead-qualified performance observer. No global
cache eviction or power/boot/default change occurs.

Next, use the verified mapping associations to construct and validate selected
native Firefox inputs with the recorded corpus-budget tradeoff. Non-mapped
reads, broker/IPC dependencies, transient loads and full input/reset/cache
closure remain open. Qualify wrapper cost before comparisons, then continue
the private package-update, game/streaming and request-attribution work. Stage 1
and the complete ten-stage goal remain active.
