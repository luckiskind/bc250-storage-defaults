# Stage 1: v2 capture around a native application

Status: two private Konsole launches pass device-wide capture integration. The
unchanged native fixture, PTY endpoint, selected data-cache states, original
session helper and normal cleanup all pass. Application overhead, foreground
attribution and the complete Stage 1 gate remain open. This is no accelerator
speed comparison.

## Integration without changing the endpoint

`bench/qualify_application_trace_v2.py` adapts the existing
[native input fixture](native-application-inputs.md). It verifies the prior
qualification's source hashes and builds a new independent corpus from the same
audit. The complete selected-node manifest must match the prior fixture.
It does not edit the original builder or terminal endpoint.

The adapter routes only the builder's exact private mount-view child invocation
to its own entry point. Mount setup, real desktop UID/groups, zero controller
capabilities, original setgid helper, private session accounting, read-only
bindings and namespace cleanup still use the original fixture. The authenticated
root cache server still verifies the exact client PID/UID, nonce and four ordered
phases before accessing the fixed private corpus. No client chooses paths,
devices, observer binaries or capture settings.

After each successful cold/warm cache preparation, the root observer attaches
the six qualified v2 programs before acknowledging the phase. The ordinary user
runs the original terminal trial and records a conservative outer time envelope
around that whole function. After normal close, the root server drains the
eight-second capture, checks all owned programs are gone, saves evidence and
then measures post-launch cache residency. Both full trial envelopes must fit
within their captures. Existing before/after endpoint snapshots must also nest
inside those envelopes. The original ready timestamp is not reconstructed or
replaced.

The outer envelope includes validation and cleanup; the snapshot envelope
includes launch and readiness validation. Neither is an exact storage-critical
interval. Startup/attach, waiting out the capture and serialization happen
outside the endpoint, but tracing and wrapper effects remain uncalibrated on
this application. Two launches cannot establish overhead, speed or tails.

## Observed result

One final-source attempt completed with exit zero on the qualified BC-250
kernel. Each capture covers its complete owned trial. Semantic stream quality
passes with no loss, unresolved records, orphans, unfinished request/return
contexts, partial requests or requeues. Raw flags remain visible for the
positively proven auxiliary records.

| Condition | Copied data resident before | Capture records | Proven internal flushes | Proven software sequences | Device reads inside snapshot envelope |
| --- | ---: | ---: | ---: | ---: | ---: |
| Selected data cold | 0 / 222,560,256 bytes | 1,284 | 9 | 9 | 99,196,928 bytes |
| Selected data warm | 222,560,256 / 222,560,256 bytes | 58 | 8 | 8 | 0 bytes |

These are observations of the **whole NVMe namespace**. Background activity,
metadata and speculative reads can contribute. The zero warm-window read count
is specific to this one envelope and is not a general application claim. Do not
divide these counts by resident pages to claim compression efficiency or read
amplification. No individual request is assigned to the foreground, and summed
request durations are not application waiting. Boundary-crossing requests are
reported separately without prorating bytes; both observed counts were zero.

All 530 copied regular files remain independently allocated, read-only and
metadata/content equivalent to the selected source set. Cold post-close
residency is 176,189,440 bytes; warm residency remains 222,560,256 bytes. Original
private session accounting passes, both terminals close normally, the cache
socket is removed and no processes remain in the unique view namespace.

The parent has 2 GiB memory, zero swap, 200% CPU, 128 tasks and a five-minute
lifetime. The selected corpus remains below 512 MiB and the 72 GiB host
free-space floor holds. As in the original fixture, Konsole can move into user
manager scopes: these are **not qualified limits on the whole foreground
application**. Retained copies/archive add lab writes and space, separate from
the unchanged production maintenance ledger. No global cache reset, power
change, reboot or suspend is performed. Suspend wake is unsupported per owner.

An independent review recomputes both summaries from retained private raw
captures. It verifies the original/copy observer hashes, unchanged native source
and selected manifest, seven installed hashes, original boot configuration,
5000 us drive policy, active enabled services and original quota charges.
The Linux regression suite passes **207 tests**.
[Reviewed aggregates](evidence/stage1-application-trace-v2.json) include every
capture; private paths, per-file identities and raw logs remain on the lab host.

## Reproduction and remaining work

This opt-in root fixture requires the prior matching ten-case v2 qualification,
the native Konsole qualification and its input audit, the existing KDE Wayland
session and the same dependencies as those fixtures. New output paths are
required. Use a short desktop output name because the Unix socket has a path
length limit.

```sh
sudo python3 bench/qualify_application_trace_v2.py run \
  --qualified /absolute/private-lab/qualified-v2 \
  --native-qualified /absolute/private-lab/qualified-native-terminal \
  --audit /absolute/private-lab/terminal-input-audit \
  --output /absolute/private-lab/new-application-trace \
  --desktop-output /absolute/private-lab/new-at2-desktop \
  --uid 1000
```

The existing [synthetic overhead screen](trace-v2-overhead.md) remains unchanged.
Next establish application/wrapper overhead with a frozen paired comparison,
then qualify filesystem/page-fault/decompression dependencies to connect device
observations to foreground progress. Complete input/context closure and the
remaining workload scenarios before comparing accelerator baselines. No
tracer is enabled in the installed profile and no default is promoted here.
