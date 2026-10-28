# Stage 1 Firefox visible-document endpoint

Status: three final-source functional checks pass. This is the second initial
application marker after [Konsole PTY readiness](workload-endpoints.md). Complete
inputs, cache conditions, activity rules and the full workload suite remain
unqualified. No storage-policy comparison or accelerator improvement is claimed.

## Defined endpoint

`bench/browser_endpoint.py` launches Firefox 156.0.1-1.1 as the desktop user with
a new private HOME, profile, configuration, data and cache tree per trial. It
uses `--no-remote --new-instance --profile`, following the [Firefox command-line
documentation](https://firefox-source-docs.mozilla.org/browser/CommandLineParameters.html).
The user's browser profile is not selected. The only private preference changes
suppress welcome/default-browser prompts; browser sandbox protections are not
disabled and no Remote Agent/debugging server is enabled.

A fixed local HTML page and SVG image are loaded from an HTTP server inside
the test's isolated network namespace. The document waits for complete load,
image decoding and font readiness, checks browser-reported visible state,
exercises a scripted button handler, and waits for two animation frames with
distinct timestamps. It then sends a nonce and a fixed-field marker to its
local controller. The controller rejects hidden/incomplete documents, incorrect
nonces, unexpected fields, ambiguous counts, invalid viewport sizes and invalid
clock values. The page's content policy allows only its controlled resources.

The endpoint is **controller receipt of browser-reported visible, scripted
document readiness**. It does not establish the first composited/displayed
frame, physical visibility through occlusion, trusted keyboard/mouse input or
general browser usability. Two animation callbacks alone do not prove display
presentation. Timing includes browser startup, page processing and local marker
delivery. The browser's own page clock is reported separately and is not
subtracted from the kernel monotonic clock.

The HTML/SVG are read into the local server's RAM before the launch timer. This
controls document/network input for an application-startup scenario; it is not
a test of physical asset-file read throughput. Firefox executable/library,
font/plugin and first-run profile behavior still need their input/cache audit.

## Isolation, ownership and cleanup

A fresh transient user service bounds the experiment to a 3 GiB cgroup memory
limit, no swap, 512 tasks and 180 seconds. No application CPU quota is requested.
Each launch has a 45-second marker deadline. These are requested test-unit
bounds, not a claim about total GPU memory or the user's whole session.

The user/network namespace maps the desktop user's ID to the same ID. The
controller brings up only that namespace's loopback interface and clears
ambient capabilities before executing Firefox. The browser parent is verified
to have zero permitted/effective/ambient capabilities and to remain in the owned
test group. The parent launcher verifies that its own network namespace stays
unchanged after the test completes.

Network verification uses actual interface/route queries: only `lo`, no IPv4 or
IPv6 default route. Mounted host sysfs can list host interfaces even from a new
network namespace, so `/sys/class/net` is not used as isolation evidence. The
desktop's Unix IPC remains available; this is browser IP-network isolation,
not isolation of all host services or proof of zero host-wide network traffic.

After the endpoint, the controller sends SIGTERM only to members of its fresh
test cgroup, using PID file descriptors and a membership recheck. It waits for
that group to contain only the controller. If necessary, a separately recorded
SIGKILL path targets remaining owned members; requiring it fails the final
functional qualification. It never stops a browser by application name.

All three accepted trials terminate the disposable browser with SIGTERM, exit
code -15, without forced cleanup. This is **owned-process cleanup**, not normal
UI quit or browser-profile durability qualification. Generated profiles/logs
remain private and disposable. A profile-preserving restart procedure is still
required before a warmed-profile performance benchmark.

## Observed checks

| Final-source trial | Launch to marker receipt | Browser marker | Cleanup |
| --- | ---: | --- | --- |
| 0 | 1.543934 s | Complete, visible, decoded image/fonts, scripted handler, two distinct frames | Owned group empty of browser processes |
| 1 | 1.571190 s | Same checks pass | Same |
| 2 | 1.577057 s | Same checks pass | Same |

Every marker has the expected 1280 × 692 content viewport, fixed CPU policy,
zero invalid markers, a capability-free browser parent and verified test-group
ownership. An earlier prototype passed one functional launch and is retained
privately. The final source adds an explicit parent membership check and avoids
signalling a process that exits/leaves membership during PID-FD acquisition.

These three times demonstrate a functioning marker, not a distribution of cold
startup latency or an acceleration result. Each profile is fresh; system page
cache is uncontrolled and no eviction occurs. First-run writes and startup
prompts differ from an established personal profile and are explicitly part
of this endpoint-development configuration.

[Reviewed evidence](evidence/stage1-browser-endpoint.json) includes source/asset
hashes, Firefox package/build IDs, all three markers, cleanup, and limits. Raw
profiles and logs are not published. Real-kernel profile/boot configuration,
5000 us drive setting and daily quota history still verify. The isolated Linux
suite passes 137 tests, including marker counterexamples. An earlier suite
invocation from outside the source root failed a local-module import and is
retained; the documented source-directory invocation passes.

## Reproduction and next work

Use Linux/Python 3.11+, the observed KDE Wayland desktop user, Firefox, iproute2,
util-linux namespaces and a user systemd manager with cgroup v2:

```sh
python3 bench/browser_endpoint.py run \
  --output /absolute/owned-lab/new-browser-endpoint --trials 3
python3 -m unittest discover -s tests -v
```

The output directory must be new with a canonical owned parent. Tests open and
close their own windows. Existing outputs, changed source during collection,
failed marker/ownership checks and incomplete cleanup are not accepted.

[Selection v2](../bench/workload-selection-v2.json) preserves the tentative
weights and all seven primary candidates from v1, updating only the Firefox
functional status and its explicit limits. It does not freeze the suite.

Next, pin complete terminal/browser inputs and choose a reproducible private
profile-reset procedure. Qualify per-workload cache state and environmental
exclusions before comparing B0/B1/B2. Keep physical asset reads, profile writes,
ELF/library loading and CPU/renderer work distinct. The private package-update
and game scene/replay/frame markers remain required parts of Stage 1.
